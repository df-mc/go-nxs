package nxs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/df-mc/go-nxs/admission"
)

const (
	// keyRenewal is how long before the retirement of the active admission key a
	// replacement is requested.
	keyRenewal = 10 * time.Minute
	// diagnosticsValidity bounds the installation of a diagnostic policy.
	diagnosticsValidity = 5 * time.Minute
)

// run sends heartbeats and outcomes until ctx is done.
func (p *Provider) run(ctx context.Context) {
	defer close(p.done)
	p.refreshEndpoints(ctx)
	now := time.Now()
	next, nextUpdate, nextEndpoints, nextOutcomes := now, now, now.Add(refreshInterval), now
	failed := false

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		now = time.Now()
		if len(p.conf.Endpoints) == 0 && now.After(nextEndpoints) {
			p.refreshEndpoints(ctx)
			nextEndpoints = now.Add(refreshInterval)
		}
		if !now.Before(next) || (p.dirty.Load() && !now.Before(nextUpdate)) {
			p.dirty.Store(false)
			n, u, err := p.heartbeat(ctx)
			if err != nil && recoverable(err) && ctx.Err() == nil {
				p.opMu.Lock()
				if rerr := p.recoverSession(ctx); rerr != nil {
					p.log.Debug("recovery failed", "error", rerr)
				} else {
					n, u, err = time.Now(), time.Now(), nil
				}
				p.opMu.Unlock()
			}
			switch {
			case err != nil && ctx.Err() == nil:
				if !failed {
					p.log.Warn("heartbeat failed", "error", err)
				}
				failed = true
				p.host.setDiagnostics(nil)
				next, nextUpdate = now.Add(10*time.Second), now.Add(10*time.Second)
			case err == nil:
				if failed {
					p.log.Info("heartbeat recovered")
				}
				failed = false
				next, nextUpdate = n, u
			}
		}
		if !now.Before(nextOutcomes) {
			nextOutcomes = now.Add(time.Second)
			if err := p.flush(ctx); err != nil && ctx.Err() == nil {
				p.log.Debug("reporting outcomes failed", "error", err)
				nextOutcomes = now.Add(10 * time.Second)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// heartbeat sends heartbeats until no immediate follow-up is needed. It returns when the
// next heartbeat is due and the earliest time an early heartbeat may be sent.
func (p *Provider) heartbeat(ctx context.Context) (next, nextUpdate time.Time, err error) {
	p.opMu.Lock()
	defer p.opMu.Unlock()
	for range 3 {
		var again bool
		if next, nextUpdate, again, err = p.exchange(ctx); err != nil || !again {
			return
		}
	}
	return time.Now().Add(time.Second), time.Now().Add(time.Second), nil
}

// exchange sends one heartbeat and reports whether another is needed immediately.
func (p *Provider) exchange(ctx context.Context) (next, nextUpdate time.Time, again bool, err error) {
	st, now := p.st, time.Now()
	if err := p.maintainKeys(now); err != nil {
		return next, nextUpdate, false, err
	}

	p.mu.Lock()
	status := p.status
	p.mu.Unlock()
	capacity := p.conf.Capacity
	if capacity == 0 && status != nil {
		capacity = status.MaxPlayers
	}
	body := heartbeatRequest{
		Capacity:            min(max(capacity, 0), 1000000),
		PlayerCount:         &playerCount{ConnectedPlayers: p.host.sessionCount(), SampledAt: now.UnixMilli()},
		Build:               p.conf.Build,
		KeyRequestID:        st.KeyRequestID,
		HostProfileRevision: p.profileRevision,
	}
	body.AcceptingPlayers = !p.closing.Load() && p.host.accepting() && p.host.hasListener() && len(st.TicketKeys) > 0 && body.Capacity > 0
	if status != nil {
		s := *status
		body.ServerStatus = &s
	}
	p.clock = max(now.UnixMilli(), p.clock+1)
	body.ClockUnixMillis = p.clock
	body.AppliedStateRevision = p.appliedState

	var profile []byte
	diagnostics := p.host.diagnosticsActive()
	if len(st.TicketKeys) > 0 {
		hp := p.hostProfile()
		if profile, err = marshal(hp); err != nil {
			return next, nextUpdate, false, err
		}
		if !bytes.Equal(profile, p.lastProfile) {
			body.HostProfile, body.HostProfileRevision = hp, ""
		}
		for _, k := range st.TicketKeys {
			body.InstalledKeyIDs = append(body.InstalledKeyIDs, k.KeyID)
		}
		if p.disc.connectivity() {
			data := map[string]any{"diagnostics": diagnostics, "candidateRevision": p.endpoints.revision, "method": p.method(), "assistedFamilies": p.assistedFamilies()}
			if !slices.Equal(p.endpoints.all, p.endpoints.published) {
				data["probeCandidates"] = nonNil(p.endpoints.all)
			}
			b, _ := json.Marshal(data)
			body.Extensions = map[string]extension{extensionConnectivity: {Version: 1, Data: b}}
		}
	}
	if body.HostProfile != nil || !p.outcomesReported {
		body.GameOutcomes = "unavailable"
		if p.conf.GameOutcomes {
			body.GameOutcomes = "available"
		}
	}

	started := time.Now()
	resp := &heartbeatResponse{}
	if err := p.signed(ctx, "heartbeat", body, resp, 3, 15*time.Second); err != nil {
		return next, nextUpdate, false, err
	}
	if !resp.Accepted {
		return next, nextUpdate, false, errors.New("nxs: heartbeat not accepted")
	}
	p.outcomesReported = true
	if body.HostProfile != nil {
		if resp.HostProfileRevision == nil || *resp.HostProfileRevision == "" {
			return next, nextUpdate, false, errors.New("nxs: host profile not acknowledged")
		}
		p.profileRevision, p.lastProfile = *resp.HostProfileRevision, profile
	}
	if again, err = p.handleKeys(resp); err != nil {
		return next, nextUpdate, false, err
	}
	p.applyFeedback(resp.Extensions)
	// Acknowledging the historic desired state never controls the listener.
	if d := resp.DesiredState; d != nil && d.State == "serving" && d.Revision >= p.appliedState && d.Revision <= 1<<53-1 {
		p.appliedState = d.Revision
	}
	if len(st.TicketKeys) > 0 && !p.closing.Load() {
		p.authority.Store(&authority{instanceID: st.Registration.InstanceID, generation: st.Generation, keyID: st.TicketKeys[len(st.TicketKeys)-1].KeyID})
	}

	p.mu.Lock()
	changed := resp.Readiness.Routable != p.readiness.Routable || !slices.Equal(resp.Readiness.Reasons, p.readiness.Reasons)
	p.readiness = resp.Readiness
	p.mu.Unlock()
	if changed {
		p.log.Info("provider readiness changed", "routable", resp.Readiness.Routable, "reasons", resp.Readiness.Reasons)
	}

	interval := time.Duration(p.disc.Limits.HeartbeatIntervalMs) * time.Millisecond
	next, nextUpdate = started.Add(interval), started.Add(interval)
	lease := time.Time{}
	if c := resp.CheckIn; c != nil && c.Version == 1 && c.AfterMillis >= 1000 {
		after := time.Duration(c.AfterMillis) * time.Millisecond
		remaining := after
		if received, err := time.Parse(time.RFC3339Nano, resp.ReceivedAt); err == nil {
			until := time.Duration(c.NextCheckInAt-max(received.UnixMilli(), time.Now().UnixMilli())) * time.Millisecond
			remaining = min(after, max(0, until))
		}
		next = started.Add(after)
		if t := time.Now().Add(remaining); t.Before(next) {
			next = t
		}
		nextUpdate = time.Now().Add(time.Duration(c.MinUpdateIntervalMillis) * time.Millisecond)
		lease = time.UnixMilli(c.LeaseExpiresAt)
	}

	if p.conf.Diagnostics && body.AcceptingPlayers {
		p.host.setDiagnostics(p.diagnosticPolicy(started, lease))
		if !diagnostics {
			// Report the installed policy.
			again = true
		}
	} else {
		p.host.setDiagnostics(nil)
	}
	return next, nextUpdate, again, nil
}

// hostProfile returns the current host profile. opMu must be held.
func (p *Provider) hostProfile() *hostProfile {
	keys := p.st.TicketKeys
	hp := &hostProfile{
		Candidates:      nonNil(p.endpoints.published),
		DTLSFingerprint: p.host.fingerprint,
		CredentialKeyID: keys[len(keys)-1].KeyID,
		SCTPPort:        sctpPort,
		MaxMessageSize:  maxMessageSize,
	}
	hp.StatelessAdmission.Capability, hp.StatelessAdmission.Incarnation = Capability, p.host.incarnation
	if p.assisting() {
		hp.StatelessAdmission.Assisted = assistedCapability
	}
	return hp
}

// maintainKeys removes retired admission keys and requests a replacement when needed.
// opMu must be held.
func (p *Provider) maintainKeys(now time.Time) error {
	st := p.st
	n := len(st.TicketKeys)
	st.TicketKeys = slices.DeleteFunc(st.TicketKeys, func(k ticketKey) bool {
		return k.RetireAfter > 0 && k.RetireAfter <= now.UnixMilli()
	})
	changed := len(st.TicketKeys) != n
	if changed {
		p.host.setKeys(st.keys())
	}
	if st.KeyRequestID == "" {
		if len(st.TicketKeys) == 0 {
			st.KeyRequestID, changed = randomID(), true
		} else if active := st.TicketKeys[len(st.TicketKeys)-1]; active.RetireAfter > 0 && len(st.TicketKeys) < 8 &&
			time.UnixMilli(active.RetireAfter).Sub(now) < keyRenewal {
			st.KeyRequestID, changed = randomID(), true
		}
	}
	if changed {
		return p.store.save(st)
	}
	return nil
}

// handleKeys installs a delivered admission key and applies key retirements. opMu must be held.
func (p *Provider) handleKeys(resp *heartbeatResponse) (again bool, err error) {
	st := p.st
	switch {
	case resp.TicketKey != nil:
		k := resp.TicketKey
		if st.KeyRequestID == "" || resp.KeyRequest == nil || resp.KeyRequest.ID != st.KeyRequestID || resp.KeyRequest.KeyID != k.KeyID {
			return false, errors.New("nxs: unbound admission key")
		}
		if !(admission.Key{ID: k.KeyID, Secret: k.Secret}).Valid() || len(st.TicketKeys) >= 8 ||
			slices.ContainsFunc(st.TicketKeys, func(t ticketKey) bool { return t.KeyID == k.KeyID }) {
			return false, errors.New("nxs: invalid admission key")
		}
		st.TicketKeys = append(st.TicketKeys, *k)
		st.KeyRequestID = ""
		if err := p.store.save(st); err != nil {
			return false, err
		}
		p.host.setKeys(st.keys())
		p.log.Debug("installed admission key", "keyID", k.KeyID)
		again = true
	case st.KeyRequestID != "" && resp.KeyRequest != nil && resp.KeyRequest.ID == st.KeyRequestID:
		// The key was delivered but its one-time response was lost.
		st.KeyRequestID = randomID()
		if err := p.store.save(st); err != nil {
			return false, err
		}
		again = true
	}
	if len(resp.Retirements) > 0 {
		changed := false
		for _, r := range resp.Retirements {
			for i, k := range st.TicketKeys {
				// Repeated replies cannot extend the life of a key.
				if k.KeyID == r.KeyID && (k.RetireAfter == 0 || r.RetireAfter < k.RetireAfter) {
					st.TicketKeys[i].RetireAfter, changed = r.RetireAfter, true
				}
			}
		}
		if changed {
			if err := p.store.save(st); err != nil {
				return false, err
			}
			p.host.setKeys(st.keys())
		}
	}
	return again, nil
}

// RotateAdmissionKey requests a replacement admission key with the next heartbeat. Older
// keys remain installed until the provider retires them.
func (p *Provider) RotateAdmissionKey() error {
	p.opMu.Lock()
	defer p.opMu.Unlock()
	if len(p.st.TicketKeys) >= 8 {
		return errors.New("nxs: wait for admission keys to retire before rotating again")
	}
	if p.st.KeyRequestID == "" {
		p.st.KeyRequestID = randomID()
		if err := p.store.save(p.st); err != nil {
			return err
		}
	}
	p.poke()
	return nil
}

func nonNil(c []candidate) []candidate {
	if c == nil {
		return []candidate{}
	}
	return c
}
