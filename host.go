package nxs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	mrand "math/rand/v2"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/df-mc/go-nethernet"
	"github.com/df-mc/go-nxs/admission"
	"github.com/pion/ice/v4"
	"github.com/pion/logging"
	"github.com/pion/stun/v4"
	"github.com/pion/webrtc/v4"
)

// admitter is implemented by [nethernet.Listener].
type admitter interface {
	Admit(ctx context.Context, a nethernet.Admission) (*nethernet.Conn, error)
}

const (
	sctpPort       = 5000
	maxMessageSize = 262144
	admitTimeout   = 20 * time.Second
)

// host accepts stateless admissions on the gameplay socket.
type host struct {
	log *slog.Logger

	conn *packetConn
	mux  *ice.UDPMuxDefault
	// settings is the base setting engine of every admitted connection.
	settings webrtc.SettingEngine

	cert        webrtc.Certificate
	fingerprint string
	incarnation string
	audience    string
	maxTTL      time.Duration

	keys        atomic.Pointer[map[string]admission.Key]
	listener    atomic.Pointer[admitter]
	diagnostics atomic.Pointer[diagnosticPolicy]
	// report records an outcome observation.
	report func(event)
	// changed is called when the number of sessions changes.
	changed func()
	// gameOutcomes reports whether game outcomes are reported for sessions.
	gameOutcomes bool

	mu       sync.Mutex
	tuples   map[netip.AddrPort]*attempt
	used     map[string]time.Time
	sessions map[uint64]*attempt
	// conns are the attempts by the ID of their Conn, from before it is established.
	conns       map[uint64]*attempt
	pending     int
	maxPending  int
	maxSessions int
	diag        diagnosticGate
	// paused stops new reservations until resumed.
	paused bool
	// stopped stops new reservations for good.
	stopped bool
}

// attempt is a reserved admission.
type attempt struct {
	token, ticketID string
	tuple           netip.AddrPort
	// first is the retained first binding request, if any.
	first []byte
	// connectionID identifies the Conn of the attempt.
	connectionID uint64
	// outcome is set once a game outcome has been reported.
	outcome atomic.Bool
}

func newHost(addr string, maxSessions int, log *slog.Logger) (*host, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("nxs: resolve address: %w", err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("nxs: listen: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	cert, err := webrtc.GenerateCertificate(key)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	fps, err := cert.GetFingerprints()
	if err != nil || len(fps) == 0 {
		_ = conn.Close()
		return nil, fmt.Errorf("nxs: certificate fingerprint: %w", err)
	}
	incarnation := make([]byte, 16)
	_, _ = rand.Read(incarnation)

	h := &host{
		log:         log,
		conn:        newPacketConn(conn),
		cert:        *cert,
		fingerprint: "sha-256 " + strings.ToUpper(fps[0].Value),
		incarnation: hex.EncodeToString(incarnation),
		maxTTL:      admission.MaxTTL,
		tuples:      make(map[netip.AddrPort]*attempt),
		used:        make(map[string]time.Time),
		sessions:    make(map[uint64]*attempt),
		conns:       make(map[uint64]*attempt),
		maxPending:  64,
		maxSessions: maxSessions,
	}
	h.audience = admission.Audience(h.incarnation)
	h.keys.Store(&map[string]admission.Key{})

	loggerFactory := logging.NewDefaultLoggerFactory()
	loggerFactory.DefaultLogLevel = logging.LogLevelError
	h.mux = ice.NewUDPMuxDefault(ice.UDPMuxParams{
		UDPConn:           h.conn,
		Logger:            loggerFactory.NewLogger("nxs"),
		OnUnhandledPacket: h.handleUnhandled,
	})
	h.settings.LoggerFactory = loggerFactory
	h.settings.SetICEUDPMux(h.mux)
	h.settings.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	// Local candidates are never signaled, but gathering one registers the token with the mux.
	h.settings.SetIncludeLoopbackCandidate(true)
	h.settings.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4, webrtc.NetworkTypeUDP6})
	return h, nil
}

// Addr returns the local address of the gameplay socket.
func (h *host) Addr() *net.UDPAddr { return h.conn.LocalAddr().(*net.UDPAddr) }

func (h *host) setKeys(keys []admission.Key) {
	m := make(map[string]admission.Key, len(keys))
	for _, k := range keys {
		m[k.ID] = k
	}
	h.keys.Store(&m)
}

func (h *host) setListener(l admitter) { h.listener.Store(&l) }

func (h *host) clearListener(l admitter) {
	if cur := h.listener.Load(); cur != nil && *cur == l {
		h.listener.Store(nil)
	}
}

func (h *host) hasListener() bool { return h.listener.Load() != nil }

// pause stops new reservations and removes the diagnostic policy.
func (h *host) pause() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.paused = true
	h.diagnostics.Store(nil)
}

// stop stops new reservations for good and removes the diagnostic policy.
func (h *host) stop() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.stopped = true
	h.diagnostics.Store(nil)
}

func (h *host) resume() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.paused = false
}

func (h *host) accepting() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.open()
}

// open reports whether new reservations are allowed. h.mu must be held.
func (h *host) open() bool { return !h.paused && !h.stopped }

func (h *host) sessionCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.sessions)
}

// handleUnhandled is called by the mux for packets that are not routed to a connection.
// It must not block, and data must be copied to be retained.
func (h *host) handleUnhandled(data []byte, addr netip.AddrPort) {
	if !stun.IsMessage(data) {
		return
	}
	msg := &stun.Message{Raw: append([]byte(nil), data...)}
	if msg.Decode() != nil || msg.Type != stun.BindingRequest {
		return
	}
	var username stun.Username
	if username.GetFrom(msg) != nil {
		return
	}
	token, clientUfrag, ok := strings.Cut(username.String(), ":")
	if !ok || !strings.HasPrefix(token, admission.Prefix) || len(token) > admission.MaxUfragLength {
		return
	}
	addr = netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())

	now := time.Now()
	keyID, _ := admission.KeyID(token)
	key, ok := (*h.keys.Load())[keyID]
	if !ok || !key.Usable(now) {
		return
	}
	claims, err := key.Open(h.audience, token, clientUfrag)
	if err != nil {
		h.log.Debug("rejected invalid admission token", "addr", addr)
		return
	}
	if !claims.ExpiresAt.After(now) || claims.ExpiresAt.Sub(now) > h.maxTTL {
		h.log.Debug("rejected expired admission token", "addr", addr)
		return
	}
	password := key.ICEPassword(h.audience, token)
	// A failed integrity check must not consume the token.
	if stun.NewShortTermIntegrity(password).Check(msg) != nil {
		h.log.Debug("rejected admission with invalid message integrity", "addr", addr)
		return
	}
	if claims.NetworkID == 0 {
		h.diagnostic(key, claims, token, clientUfrag, password, addr, msg.Raw)
		return
	}

	a, ok := h.reserve(token, addr, claims.ExpiresAt, msg.Raw)
	if !ok {
		return
	}
	h.emit(a, "ticket.ice_seen", "token_and_stun_validated", nil)
	go h.establish(a, nethernet.Admission{
		NetworkID:       strconv.FormatUint(claims.NetworkID, 10),
		ICE:             webrtc.ICEParameters{UsernameFragment: clientUfrag, Password: claims.Password},
		DTLS:            remoteDTLS(claims.Fingerprint[:]),
		SCTP:            webrtc.SCTPCapabilities{MaxMessageSize: claims.MaxMessageSize},
		VerifyPublicKey: h.verifier(a, key, claims),
	}, password)
}

// remoteDTLS returns the DTLS parameters of a client with the certificate fingerprint.
func remoteDTLS(fingerprint []byte) webrtc.DTLSParameters {
	// The provider answers with 'a=setup:active', so the host is the DTLS client.
	return webrtc.DTLSParameters{
		Role:         webrtc.DTLSRoleServer,
		Fingerprints: []webrtc.DTLSFingerprint{{Algorithm: "sha-256", Value: colonHex(fingerprint)}},
	}
}

// reserve reserves an admission, rejecting replays and conflicting tuples.
func (h *host) reserve(token string, addr netip.AddrPort, expiry time.Time, first []byte) (*attempt, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	for t, exp := range h.used {
		if !exp.After(now) {
			delete(h.used, t)
		}
	}
	if _, ok := h.used[token]; ok {
		// Either a retransmission of a pending attempt or a replay.
		return nil, false
	}
	if _, ok := h.tuples[addr]; ok || !h.open() || h.pending >= h.maxPending || (h.maxSessions > 0 && len(h.sessions)+h.pending >= h.maxSessions) {
		return nil, false
	}
	a := &attempt{token: token, ticketID: admission.TicketID(token), tuple: addr, first: first}
	h.used[token] = expiry
	if addr.IsValid() {
		h.tuples[addr] = a
	}
	h.pending++
	return a, true
}

// establish admits the connection of a reserved attempt into the listener, using password
// as the local ICE password for the token of the attempt.
func (h *host) establish(a *attempt, adm nethernet.Admission, password string) {
	conn, err := h.connect(a, adm, password, admitTimeout)
	if err != nil {
		h.fail(a, failureReason(err), err)
		return
	}
	var remote *netip.AddrPort
	if addr, ok := conn.RemoteAddr().(*nethernet.Addr); ok && addr.SelectedCandidate != nil {
		if ip, err := netip.ParseAddr(addr.SelectedCandidate.Address); err == nil {
			ap := netip.AddrPortFrom(ip, addr.SelectedCandidate.Port)
			remote = &ap
		}
	}
	h.emit(a, "ticket.data_channels_open", "", remote)

	h.mu.Lock()
	h.pending--
	h.sessions[a.connectionID] = a
	h.mu.Unlock()
	h.changed()

	<-conn.Context().Done()
	h.mu.Lock()
	delete(h.sessions, a.connectionID)
	delete(h.tuples, a.tuple)
	h.mu.Unlock()
	h.changed()
}

// connect establishes the Conn of an attempt, completing adm with the local parameters.
func (h *host) connect(a *attempt, adm nethernet.Admission, password string, timeout time.Duration) (*nethernet.Conn, error) {
	l := h.listener.Load()
	if l == nil {
		return nil, errNoListener
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	settings := h.settings
	settings.SetICECredentials(a.token, password)
	a.connectionID = mrand.Uint64()
	adm.ConnectionID = a.connectionID
	h.mu.Lock()
	h.conns[a.connectionID] = a
	h.mu.Unlock()
	adm.API = webrtc.NewAPI(webrtc.WithSettingEngine(settings))
	adm.Certificates = []webrtc.Certificate{h.cert}
	var replay sync.Once
	adm.OnICEStateChange = func(state webrtc.ICETransportState) {
		switch state {
		case webrtc.ICETransportStateChecking:
			if a.first != nil {
				// The agent can only answer the retained request once it has started.
				replay.Do(func() { h.conn.inject(a.first, a.tuple) })
			}
		case webrtc.ICETransportStateConnected:
			if !adm.Detached {
				h.emit(a, "ticket.ice_connected", "", nil)
			}
		}
	}
	conn, err := (*l).Admit(ctx, adm)
	if err != nil {
		h.mu.Lock()
		delete(h.conns, a.connectionID)
		h.mu.Unlock()
		if ctx.Err() != nil {
			err = errors.Join(errTimeout, err)
		}
		return nil, err
	}
	context.AfterFunc(conn.Context(), func() {
		h.mu.Lock()
		delete(h.conns, a.connectionID)
		h.mu.Unlock()
	})
	return conn, nil
}

// gameOutcome reports the game outcome of the session of addr.
func (h *host) gameOutcome(addr net.Addr, stage, reason string) {
	na, ok := addr.(*nethernet.Addr)
	if !ok || !h.gameOutcomes {
		return
	}
	h.mu.Lock()
	a, ok := h.conns[na.ConnectionID]
	h.mu.Unlock()
	if ok && !a.outcome.Swap(true) {
		h.emit(a, stage, reason, nil)
	}
}

func (h *host) fail(a *attempt, reason string, err error) {
	h.log.Debug("admission failed", "reason", reason, "addr", a.tuple, "error", err)
	h.emit(a, "ticket.failed", reason, nil)
	h.mu.Lock()
	h.pending--
	delete(h.tuples, a.tuple)
	h.mu.Unlock()
}

func (h *host) emit(a *attempt, stage, reason string, remote *netip.AddrPort) {
	e := event{TicketID: a.ticketID, Stage: stage, OccurredAt: time.Now().UTC().Format(time.RFC3339Nano), Reason: reason}
	if remote != nil {
		e.RemoteAddress, e.RemotePort = remote.Addr().String(), int(remote.Port())
	}
	h.report(e)
}

// verifier returns a one-shot check of the login identity key against the admission.
func (h *host) verifier(a *attempt, key admission.Key, claims admission.Claims) func(*ecdsa.PublicKey) error {
	deadline := time.Now().Add(time.Until(claims.ExpiresAt))
	var used atomic.Bool
	return func(pub *ecdsa.PublicKey) error {
		if used.Swap(true) {
			return errors.New("nxs: admission identity already verified")
		}
		var err error
		if time.Now().After(deadline) {
			err = errors.New("nxs: admission expired before login")
		} else if !key.VerifyBinding(h.audience, pub, claims.IdentityBinding) {
			err = errors.New("nxs: login identity does not match admission")
		}
		if err != nil && h.gameOutcomes && !a.outcome.Swap(true) {
			h.emit(a, "ticket.game_rejected", "identity_mismatch", nil)
		}
		return err
	}
}

var (
	errNoListener = errors.New("nxs: no listener attached")
	errTimeout    = errors.New("nxs: admission timed out")
)

func failureReason(err error) string {
	switch {
	case errors.Is(err, errNoListener):
		return "no_listener"
	case errors.Is(err, errTimeout):
		return "timeout"
	case errors.Is(err, net.ErrClosed):
		return "closed"
	case strings.Contains(err.Error(), "DTLS"):
		return "dtls_failed"
	case strings.Contains(err.Error(), "ICE"):
		return "ice_failed"
	case strings.Contains(err.Error(), "SCTP"):
		return "sctp_failed"
	}
	return "transport_failed"
}

func colonHex(b []byte) string {
	s := strings.ToUpper(hex.EncodeToString(b))
	parts := make([]string, len(b))
	for i := range b {
		parts[i] = s[2*i : 2*i+2]
	}
	return strings.Join(parts, ":")
}

// close closes the mux, which also closes the gameplay socket.
func (h *host) close() error {
	return h.mux.Close()
}
