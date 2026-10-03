package nxs

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/df-mc/go-nethernet"
	"github.com/df-mc/go-nxs/admission"
	"github.com/pion/webrtc/v4"
)

func testLog() *slog.Logger {
	level := slog.LevelWarn
	if os.Getenv("NXS_DEBUG") != "" {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

// freeEndpoint returns a loopback UDP endpoint that is currently unused.
func freeEndpoint(t *testing.T) netip.AddrPort {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).AddrPort()
}

// startProvider starts a Provider and a Listener against f. The endpoint of the Provider
// is its only advertised candidate.
func startProvider(t *testing.T, f *fakeProvider, conf Config) (*Provider, *nethernet.Listener, netip.AddrPort) {
	t.Helper()
	endpoint := freeEndpoint(t)
	conf.Origin, conf.Address, conf.Endpoints, conf.Log = f.origin, endpoint.String(), []netip.AddrPort{endpoint}, testLog()
	if conf.StateDir == "" {
		conf.StateDir = t.TempDir()
	}
	if conf.Capacity == 0 {
		conf.Capacity = 10
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	p, err := New(ctx, conf)
	if err != nil {
		t.Fatal(err)
	}
	l, err := nethernet.ListenConfig{Log: testLog()}.Listen(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = l.Close()
		_ = p.Close()
	})
	l.PongData([]byte("MCPE;Test;1000;1.26.0;0;10;1;world;Survival;1;0;0;0;0;"))
	waitFor(t, func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.profile != nil && len(f.heartbeats) > 0 && f.heartbeats[len(f.heartbeats)-1].AcceptingPlayers
	})
	return p, l, endpoint
}

// joinSignaling hands the offer of a player to answer, as a provider does.
type joinSignaling struct {
	answer func(offer *nethernet.Signal) (string, error)

	mu        sync.Mutex
	notifiers []nethernet.Notifier
}

func (s *joinSignaling) Signal(_ context.Context, signal *nethernet.Signal) error {
	if signal.Type != nethernet.SignalTypeOffer {
		return nil
	}
	answer, err := s.answer(signal)
	if err != nil {
		return err
	}
	s.mu.Lock()
	notifiers := s.notifiers
	s.mu.Unlock()
	go func() {
		for _, n := range notifiers {
			n.NotifySignal(&nethernet.Signal{Type: nethernet.SignalTypeAnswer, ConnectionID: signal.ConnectionID, NetworkID: signal.NetworkID, Data: answer})
		}
	}()
	return nil
}

func (s *joinSignaling) Notify(n nethernet.Notifier) func() {
	s.mu.Lock()
	s.notifiers = append(s.notifiers, n)
	s.mu.Unlock()
	return func() {}
}

func (*joinSignaling) Context() context.Context { return context.Background() }
func (*joinSignaling) Credentials(context.Context) (*nethernet.Credentials, error) {
	return nil, nil
}
func (*joinSignaling) NetworkID() string       { return "42" }
func (*joinSignaling) PongData([]byte)         {}
func (*joinSignaling) DisableTrickleICE() bool { return true }

// dialer returns a Dialer acting as a player on loopback. password optionally fixes its
// local ICE password.
func dialer(password string) nethernet.Dialer {
	settings := webrtc.SettingEngine{}
	settings.SetIncludeLoopbackCandidate(true)
	settings.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4})
	if password != "" {
		settings.SetICECredentials("proberUfrag", password)
	}
	return nethernet.Dialer{API: webrtc.NewAPI(webrtc.WithSettingEngine(settings)), AllowIdentitylessServer: true, DisableTrickleICE: true, Log: testLog()}
}

func sdpField(sdp, name string) string {
	for _, line := range strings.Split(sdp, "\r\n") {
		if v, ok := strings.CutPrefix(line, "a="+name+":"); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// statelessAnswer seals the offer of a player into an answer from the profile of f.
func statelessAnswer(f *fakeProvider, host netip.AddrPort, networkID uint64, binding func(audience string, key admission.Key) [16]byte, diag *admission.Diagnostic) func(*nethernet.Signal) (string, error) {
	return func(signal *nethernet.Signal) (string, error) {
		ufrag, pwd, fp := sdpField(signal.Data, "ice-ufrag"), sdpField(signal.Data, "ice-pwd"), sdpField(signal.Data, "fingerprint")
		f.mu.Lock()
		profile := f.profile
		f.mu.Unlock()
		key, _ := f.key(profile.CredentialKeyID)
		audience := admission.Audience(profile.StatelessAdmission.Incarnation)
		c := admission.Claims{ExpiresAt: time.Unix(time.Now().Add(30*time.Second).Unix(), 0), SCTPPort: 5000, MaxMessageSize: 262144,
			NetworkID: networkID, Password: pwd, Diagnostic: diag}
		raw, _ := hex.DecodeString(strings.ReplaceAll(strings.TrimPrefix(fp, "sha-256 "), ":", ""))
		copy(c.Fingerprint[:], raw)
		c.IdentityBinding = binding(audience, key)
		var nonce [12]byte
		_, _ = rand.Read(nonce[:])
		token, err := key.Seal(audience, ufrag, c, nonce)
		if err != nil {
			return "", err
		}
		return answer(token, key.ICEPassword(audience, token), profile.DTLSFingerprint, []candidate{{Address: host.Addr().String(), Port: host.Port(), Type: "host"}}), nil
	}
}

func identityBinding(pub *ecdsa.PublicKey) func(string, admission.Key) [16]byte {
	return func(audience string, key admission.Key) [16]byte {
		b, _ := key.Binding(audience, pub)
		return b
	}
}

// join dials a player and returns both ends of the connection.
func join(t *testing.T, l *nethernet.Listener, d nethernet.Dialer, s nethernet.Signaling) (client, server *nethernet.Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	accepted := make(chan *nethernet.Conn, 1)
	go func() {
		if c, err := l.Accept(); err == nil {
			accepted <- c.(*nethernet.Conn)
		}
	}()
	client, err := d.DialContext(ctx, "host", s)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	select {
	case server = <-accepted:
	case <-ctx.Done():
		t.Fatal("no connection accepted")
	}
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 5)
	if _, err := io.ReadFull(server, b); err != nil || string(b) != "hello" {
		t.Fatalf("read %q: %v", b, err)
	}
	return client, server
}

func TestProvider(t *testing.T) {
	f := newFakeProvider(t)
	dir := t.TempDir()
	p, l, host := startProvider(t, f, Config{StateDir: dir, GameOutcomes: true})
	if p.PublicAddress() != "https://test.example" || !strings.Contains(string(p.Extensions()["com.example.claim"]), "claim.example") {
		t.Fatalf("unexpected registration metadata: %s, %v", p.PublicAddress(), p.Extensions())
	}
	if f.lastHeartbeat().GameOutcomes != "" && f.lastHeartbeat().GameOutcomes != "available" {
		t.Fatalf("unexpected game outcomes %q", f.lastHeartbeat().GameOutcomes)
	}

	identity, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	for i, wantOK := range []bool{true, false} {
		s := &joinSignaling{answer: statelessAnswer(f, host, 42, identityBinding(&identity.PublicKey), nil)}
		client, server := join(t, l, dialer(""), s)
		if server.RemoteAddr().(*nethernet.Addr).NetworkID != "42" {
			t.Fatalf("unexpected network ID %s", server.RemoteAddr())
		}
		key := &identity.PublicKey
		if !wantOK {
			other, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			key = &other.PublicKey
		}
		if err := server.VerifyPublicKey(key); (err == nil) != wantOK {
			t.Fatalf("join %d: VerifyPublicKey: %v, want ok %v", i, err, wantOK)
		}
		if server.VerifyPublicKey(&identity.PublicKey) == nil {
			t.Fatal("VerifyPublicKey should be one-shot")
		}
		if wantOK {
			p.GameJoined(server)
		}
		_ = client.Close()
		_ = server.Close()
	}
	waitFor(t, func() bool {
		ok := f.countEvents("ticket.data_channels_open") == 2 && f.countEvents("ticket.game_joined") == 1 && f.countEvents("ticket.game_rejected") == 1
		if !ok && os.Getenv("NXS_DEBUG") != "" {
			f.mu.Lock()
			t.Logf("events: %+v", f.events)
			f.mu.Unlock()
		}
		return ok
	})

	if err := p.ExtensionRequest(context.Background(), "com.example.claim", "refresh", "POST", map[string]any{"events": []any{}}, nil); err != nil {
		t.Fatalf("extension request: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if f.lastHeartbeat().AcceptingPlayers {
		t.Fatal("final heartbeat should stop accepting players")
	}

	// A restart recovers the saved registration and keeps its admission key.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	p, err := New(ctx, Config{Origin: f.origin, StateDir: dir, Address: "127.0.0.1:0", Log: testLog()})
	if err != nil {
		t.Fatal(err)
	}
	p.opMu.Lock()
	keys := len(p.st.TicketKeys)
	p.opMu.Unlock()
	if p.NetworkID() != "instance_1" || keys != 1 {
		t.Fatalf("unexpected recovered state: %s, %d keys", p.NetworkID(), keys)
	}
	if err := p.Deregister(ctx); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	if strings.Contains(string(b), "instance_1") {
		t.Fatal("state should be reset after deregistration")
	}
}

func TestPause(t *testing.T) {
	f := newFakeProvider(t)
	p, l, host := startProvider(t, f, Config{Diagnostics: true})
	identity, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	s := &joinSignaling{answer: statelessAnswer(f, host, 42, identityBinding(&identity.PublicKey), nil)}
	client, server := join(t, l, dialer(""), s)
	defer client.Close()
	defer server.Close()
	waitFor(t, p.host.diagnosticsActive)

	p.Pause()
	waitFor(t, func() bool {
		hb := f.lastHeartbeat()
		return !hb.AcceptingPlayers && hb.PlayerCount != nil && hb.PlayerCount.ConnectedPlayers == 1
	})
	if p.host.diagnosticsActive() {
		t.Fatal("diagnostics should be disabled while paused")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if c, err := dialer("").DialContext(ctx, "host", s); err == nil {
		_ = c.Close()
		t.Fatal("a paused host should not admit players")
	}
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 5)
	if _, err := io.ReadFull(server, b); err != nil || string(b) != "hello" {
		t.Fatalf("read %q: %v", b, err)
	}

	p.Resume()
	waitFor(t, func() bool { return f.lastHeartbeat().AcceptingPlayers && p.host.diagnosticsActive() })
	c, sc := join(t, l, dialer(""), s)
	_ = c.Close()
	_ = sc.Close()

	_ = p.Close()
	p.Resume()
	if p.host.accepting() {
		t.Fatal("a closed host should not resume admitting players")
	}
}

func TestPauseDiagnostics(t *testing.T) {
	h := &host{}
	h.pause()
	h.setDiagnostics(&diagnosticPolicy{expires: time.Now().Add(time.Minute)})
	if h.diagnosticsActive() {
		t.Fatal("a paused host should not install a diagnostic policy")
	}
}

func TestAssistedJoin(t *testing.T) {
	f := newFakeProvider(t)
	p, l, _ := startProvider(t, f, Config{AssistedJoins: true})
	waitFor(t, func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.wsHeartbeats > 0 && f.profile.StatelessAdmission.Assisted == assistedCapability
	})

	identity, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	cpk, _ := admission.CanonicalPublicKey(&identity.PublicKey)
	s := &joinSignaling{answer: func(signal *nethernet.Signal) (string, error) {
		f.mu.Lock()
		profile, gen := f.profile, f.generation
		f.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return f.assist(ctx, map[string]any{
			"instanceId": "instance_1", "generation": gen, "incarnation": profile.StatelessAdmission.Incarnation,
			"keyId": profile.CredentialKeyID, "hostFingerprint": profile.DTLSFingerprint,
			"expiresAt": time.Now().Add(20 * time.Second).UnixMilli(), "networkId": "43", "cpk": cpk,
			"localUfrag": "assistedHostUfrag", "localPassword": "assistedHostPassword0123456789",
			"offer": signal.Data,
		})
	}}
	p.Pause()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if c, err := dialer("").DialContext(ctx, "host", s); err == nil {
		_ = c.Close()
		t.Fatal("a paused host should not admit assisted joins")
	}
	p.Resume()

	client, server := join(t, l, dialer(""), s)
	defer client.Close()
	defer server.Close()
	if server.RemoteAddr().(*nethernet.Addr).NetworkID != "43" {
		t.Fatalf("unexpected network ID %s", server.RemoteAddr())
	}
	if err := server.VerifyPublicKey(&identity.PublicKey); err != nil {
		t.Fatalf("VerifyPublicKey: %v", err)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if server.VerifyPublicKey(&other.PublicKey) == nil {
		t.Fatal("VerifyPublicKey should reject another identity")
	}
}

func TestDiagnostics(t *testing.T) {
	f := newFakeProvider(t)
	_, l, host := startProvider(t, f, Config{Diagnostics: true})
	var revision int64
	waitFor(t, func() bool {
		var data struct {
			Diagnostics       bool  `json:"diagnostics"`
			CandidateRevision int64 `json:"candidateRevision"`
		}
		_ = json.Unmarshal(f.lastHeartbeat().Extensions[extensionConnectivity].Data, &data)
		revision = data.CandidateRevision
		return data.Diagnostics
	})

	var attemptID [16]byte
	_, _ = rand.Read(attemptID[:])
	diag := &admission.Diagnostic{CandidateRevision: uint64(revision), Profile: admission.ProfileDirect, Target: host}
	s := &joinSignaling{answer: statelessAnswer(f, host, 0, func(string, admission.Key) [16]byte { return attemptID }, diag)}
	accepted := make(chan struct{}, 1)
	go func() {
		if c, err := l.Accept(); err == nil {
			_ = c.Close()
			accepted <- struct{}{}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client, err := dialer("proberPassword0123456789").DialContext(ctx, "host", s)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	var nonce [32]byte
	_, _ = rand.Read(nonce[:])
	ping := append(append([]byte{0x4e, 0x58, 0x44, 0x50, 0x01, diagnosticPing, 0}, attemptID[:]...), nonce[:]...)
	if _, err := client.Write(ping); err != nil {
		t.Fatal(err)
	}
	pong, err := client.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	want := bytes.Clone(ping)
	want[5] = diagnosticPong
	if !bytes.Equal(pong, want) {
		t.Fatalf("unexpected PONG %x", pong)
	}
	select {
	case <-accepted:
		t.Fatal("diagnostic connection should not be accepted")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestRecovery(t *testing.T) {
	f := newFakeProvider(t)
	startProvider(t, f, Config{})
	f.mu.Lock()
	f.fence = true
	f.mu.Unlock()
	waitFor(t, func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.generation == 2 && f.heartbeats[len(f.heartbeats)-1].HostProfile != nil
	})
}

func TestConnectivityFeedback(t *testing.T) {
	f := newFakeProvider(t)
	_, _, host := startProvider(t, f, Config{})
	now := time.Now().UnixMilli()
	check := connectivityCheck{Region: "eu", Family: 4, Outcome: "not-established", CheckedAt: now - 1000, ExpiresAt: now + 60000}
	check.Target = &struct {
		Address string `json:"address"`
		Port    uint16 `json:"port"`
	}{host.Addr().String(), host.Port()}
	f.mu.Lock()
	f.feedback = []connectivityCheck{check}
	f.mu.Unlock()
	waitFor(t, func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return len(f.profile.Candidates) == 0
	})
	var data struct {
		ProbeCandidates []candidate `json:"probeCandidates"`
	}
	_ = json.Unmarshal(f.lastHeartbeat().Extensions[extensionConnectivity].Data, &data)
	if len(data.ProbeCandidates) != 1 || data.ProbeCandidates[0].Port != host.Port() {
		t.Fatalf("withheld endpoint should remain a probe candidate: %+v", data.ProbeCandidates)
	}
}

func TestAdmissionKeyRotation(t *testing.T) {
	f := newFakeProvider(t)
	startProvider(t, f, Config{})
	f.mu.Lock()
	f.retireAfter = time.Now().Add(5 * time.Minute).UnixMilli()
	f.mu.Unlock()
	waitFor(t, func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.profile.CredentialKeyID == "K002" && slices2(f.heartbeats[len(f.heartbeats)-1].InstalledKeyIDs, "K001", "K002")
	})
}

func slices2(ids []string, a, b string) bool { return len(ids) == 2 && ids[0] == a && ids[1] == b }

func TestMachineKeyRotation(t *testing.T) {
	f := newFakeProvider(t)
	p, _, _ := startProvider(t, f, Config{})
	if err := p.RotateMachineKey(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	n := len(f.heartbeats)
	f.mu.Unlock()
	waitFor(t, func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return len(f.heartbeats) > n+1
	})
	p.opMu.Lock()
	defer p.opMu.Unlock()
	if p.st.Registration.KeyID != "key_2" || p.st.PendingPrivateKey != "" {
		t.Fatalf("unexpected state after rotation: %s", p.st.Registration.KeyID)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestAssistedDiagnostic(t *testing.T) {
	f := newFakeProvider(t)
	startProvider(t, f, Config{AssistedJoins: true, Diagnostics: true})
	var revision int64
	waitFor(t, func() bool {
		var data struct {
			Diagnostics       bool  `json:"diagnostics"`
			CandidateRevision int64 `json:"candidateRevision"`
			AssistedFamilies  []int `json:"assistedFamilies"`
		}
		_ = json.Unmarshal(f.lastHeartbeat().Extensions[extensionConnectivity].Data, &data)
		revision = data.CandidateRevision
		f.mu.Lock()
		defer f.mu.Unlock()
		return data.Diagnostics && len(data.AssistedFamilies) == 1 && f.wsHeartbeats > 0
	})

	var attemptID [16]byte
	_, _ = rand.Read(attemptID[:])
	s := &joinSignaling{answer: func(signal *nethernet.Signal) (string, error) {
		f.mu.Lock()
		profile, gen := f.profile, f.generation
		f.mu.Unlock()
		key, _ := f.key(profile.CredentialKeyID)
		audience := admission.Audience(profile.StatelessAdmission.Incarnation)
		fp, _ := hex.DecodeString(strings.ReplaceAll(strings.TrimPrefix(sdpField(signal.Data, "fingerprint"), "sha-256 "), ":", ""))
		c := admission.Claims{ExpiresAt: time.Unix(time.Now().Add(30*time.Second).Unix(), 0), SCTPPort: 5000, MaxMessageSize: 262144,
			Password: sdpField(signal.Data, "ice-pwd"), IdentityBinding: attemptID,
			Diagnostic: &admission.Diagnostic{OfferDigest: sha256.Sum256([]byte(signal.Data)), CandidateRevision: uint64(revision),
				Profile: admission.ProfileAssisted, Target: netip.AddrPortFrom(netip.IPv4Unspecified(), 0)}}
		copy(c.Fingerprint[:], fp)
		token, err := key.Seal(audience, sdpField(signal.Data, "ice-ufrag"), c, [12]byte{1})
		if err != nil {
			return "", err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return f.assist(ctx, map[string]any{
			"instanceId": "instance_1", "generation": gen, "incarnation": profile.StatelessAdmission.Incarnation,
			"keyId": profile.CredentialKeyID, "hostFingerprint": profile.DTLSFingerprint,
			"expiresAt": c.ExpiresAt.UnixMilli(), "networkId": "0",
			"localUfrag": token, "localPassword": key.ICEPassword(audience, token), "offer": signal.Data,
		})
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client, err := dialer("proberPassword0123456789").DialContext(ctx, "host", s)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	ping := append(append([]byte{0x4e, 0x58, 0x44, 0x50, 0x01, diagnosticPing, 0}, attemptID[:]...), make([]byte, 32)...)
	if _, err := client.Write(ping); err != nil {
		t.Fatal(err)
	}
	pong, err := client.ReadPacket()
	if err != nil || len(pong) != 55 || pong[5] != diagnosticPong {
		t.Fatalf("unexpected PONG %x: %v", pong, err)
	}
}
