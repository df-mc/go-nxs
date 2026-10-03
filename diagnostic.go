package nxs

import (
	"bytes"
	"errors"
	"net/netip"
	"time"

	"github.com/df-mc/go-nethernet"
	"github.com/df-mc/go-nxs/admission"
	"github.com/pion/webrtc/v4"
)

const (
	maxDiagnosticAttempts = 4
	maxDiagnosticHistory  = 16
	maxDiagnosticLifetime = 60 * time.Second
	diagnosticHandshake   = 15 * time.Second
	diagnosticLinger      = time.Second
)

// diagnosticMagic prefixes a diagnostic frame after the NetherNet segment header.
var diagnosticMagic = []byte{0x4e, 0x58, 0x44, 0x50, 0x01}

const (
	diagnosticPing = 2
	diagnosticPong = 3
)

// diagnosticPolicy authorizes diagnostic admissions until it expires.
type diagnosticPolicy struct {
	expires  time.Time
	revision int64
	keys     map[string]admission.Key
	// endpoints are the direct targets and their expiry.
	endpoints map[netip.AddrPort]time.Time
	// assisted are the address families of assisted targets.
	assisted map[int]bool
}

// diagnosticGate bounds diagnostic attempts. It is guarded by host.mu.
type diagnosticGate struct {
	active int
	used   map[[16]byte]time.Time
}

// diagnosticPolicy returns the policy installed after a heartbeat at now. opMu must be held.
func (p *Provider) diagnosticPolicy(now, lease time.Time) *diagnosticPolicy {
	expires := now.Add(diagnosticsValidity)
	if !lease.IsZero() && lease.Before(expires) {
		expires = lease
	}
	pol := &diagnosticPolicy{
		expires:   expires,
		revision:  p.endpoints.revision,
		keys:      make(map[string]admission.Key),
		endpoints: make(map[netip.AddrPort]time.Time),
		assisted:  make(map[int]bool),
	}
	for _, k := range p.st.keys() {
		pol.keys[k.ID] = k
	}
	for _, c := range p.endpoints.all {
		addr, err := netip.ParseAddr(c.Address)
		if err != nil {
			continue
		}
		exp := expires
		if c.ExpiresAt > 0 && time.UnixMilli(c.ExpiresAt).Before(exp) {
			exp = time.UnixMilli(c.ExpiresAt)
		}
		pol.endpoints[netip.AddrPortFrom(addr, c.Port)] = exp
	}
	for _, f := range p.assistedFamilies() {
		pol.assisted[f] = true
	}
	return pol
}

// setDiagnostics installs pol. A heartbeat racing Pause cannot install a policy.
func (h *host) setDiagnostics(pol *diagnosticPolicy) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if pol == nil || h.open() {
		h.diagnostics.Store(pol)
	}
}

// diagnosticsActive reports whether a diagnostic policy is installed.
func (h *host) diagnosticsActive() bool {
	pol := h.diagnostics.Load()
	return pol != nil && time.Now().Before(pol.expires)
}

// authorizeDiagnostic checks the claims of a diagnostic against the installed policy.
func (h *host) authorizeDiagnostic(key admission.Key, claims admission.Claims, family int) error {
	pol, now, d := h.diagnostics.Load(), time.Now(), claims.Diagnostic
	if pol == nil || !now.Before(pol.expires) {
		return errors.New("no diagnostic policy installed")
	}
	if k, ok := pol.keys[key.ID]; !ok || k.Secret != key.Secret {
		return errors.New("admission key not authorized for diagnostics")
	}
	if d.Family() != family || int64(d.CandidateRevision) != pol.revision || claims.SCTPPort != sctpPort || claims.MaxMessageSize != maxMessageSize {
		return errors.New("diagnostic does not match the published profile")
	}
	expiry := pol.expires
	switch d.Profile {
	case admission.ProfileDirect:
		exp, ok := pol.endpoints[d.Target]
		if !ok {
			return errors.New("diagnostic target is not published")
		}
		expiry = exp
	case admission.ProfileAssisted:
		if !pol.assisted[family] {
			return errors.New("assisted diagnostics are not enabled for the family")
		}
	}
	if remaining := time.Until(claims.ExpiresAt); remaining <= 0 || remaining > maxDiagnosticLifetime || claims.ExpiresAt.After(expiry) {
		return errors.New("diagnostic expires outside of its authorization")
	}
	return nil
}

// diagnostic admits a direct diagnostic received in the first binding request from addr.
func (h *host) diagnostic(key admission.Key, claims admission.Claims, token, clientUfrag, password string, addr netip.AddrPort, first []byte) {
	family := 4
	if addr.Addr().Is6() {
		family = 6
	}
	if claims.Diagnostic.Profile != admission.ProfileDirect {
		// An unknown assisted diagnostic cannot create a peer.
		return
	}
	if err := h.authorizeDiagnostic(key, claims, family); err != nil {
		h.log.Debug("rejected diagnostic", "addr", addr, "error", err)
		return
	}
	a, ok := h.reserveDiagnostic(token, addr, claims, first)
	if !ok {
		return
	}
	go h.echo(a, nethernet.Admission{
		NetworkID: "0",
		ICE:       webrtc.ICEParameters{UsernameFragment: clientUfrag, Password: claims.Password},
		DTLS:      remoteDTLS(claims.Fingerprint[:]),
		SCTP:      webrtc.SCTPCapabilities{MaxMessageSize: claims.MaxMessageSize},
	}, password, claims)
}

// reserveDiagnostic reserves a diagnostic attempt within the bounds of the gate.
func (h *host) reserveDiagnostic(token string, addr netip.AddrPort, claims admission.Claims, first []byte) (*attempt, bool) {
	id := claims.IdentityBinding
	h.mu.Lock()
	now := time.Now()
	if h.diag.used == nil {
		h.diag.used = make(map[[16]byte]time.Time)
	}
	for k, exp := range h.diag.used {
		if !exp.After(now) {
			delete(h.diag.used, k)
		}
	}
	_, seen := h.diag.used[id]
	if seen || h.diag.active >= maxDiagnosticAttempts || len(h.diag.used) >= maxDiagnosticHistory {
		h.mu.Unlock()
		return nil, false
	}
	h.mu.Unlock()
	a, ok := h.reserve(token, addr, claims.ExpiresAt, first)
	if !ok {
		return nil, false
	}
	h.mu.Lock()
	h.diag.active++
	h.diag.used[id] = claims.ExpiresAt
	h.mu.Unlock()
	return a, true
}

// echo establishes a diagnostic connection, answers its PING and closes it.
func (h *host) echo(a *attempt, adm nethernet.Admission, password string, claims admission.Claims) {
	defer func() {
		h.mu.Lock()
		h.diag.active--
		h.pending--
		delete(h.tuples, a.tuple)
		h.mu.Unlock()
	}()
	adm.Detached = true
	deadline := min(diagnosticHandshake, time.Until(claims.ExpiresAt))
	conn, err := h.connect(a, adm, password, deadline)
	if err != nil {
		h.log.Debug("diagnostic failed", "error", err)
		return
	}
	defer conn.Close()
	timer := time.AfterFunc(deadline, func() { _ = conn.Close() })
	defer timer.Stop()

	b, err := conn.ReadPacket()
	if err != nil {
		h.log.Debug("diagnostic failed", "error", err)
		return
	}
	pong, err := diagnosticReply(b, claims.IdentityBinding)
	if err != nil {
		h.log.Debug("diagnostic failed", "error", err)
		return
	}
	if _, err := conn.Write(pong); err != nil {
		return
	}
	h.log.Debug("answered diagnostic", "addr", conn.RemoteAddr())
	// Give the prober a moment to close first.
	select {
	case <-conn.Context().Done():
	case <-time.After(diagnosticLinger):
	}
}

// diagnosticReply returns the PONG for a PING of the attempt, both without the NetherNet
// segment header.
func diagnosticReply(ping []byte, attemptID [16]byte) ([]byte, error) {
	if len(ping) != 55 || !bytes.HasPrefix(ping, diagnosticMagic) || ping[5] != diagnosticPing || ping[6] != 0 || !bytes.Equal(ping[7:23], attemptID[:]) {
		return nil, errors.New("invalid diagnostic PING")
	}
	pong := bytes.Clone(ping)
	pong[5] = diagnosticPong
	return pong, nil
}
