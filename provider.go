// Package nxs implements a NetherNet host for providers of NetherNet External Signaling
// (NXS), such as Warden. The provider handles signaling with players and routes them to
// the host, which admits connections from stateless tokens carried in their first STUN
// request.
//
// A Provider implements [nethernet.Signaling] and is used to listen with a
// [nethernet.ListenConfig]:
//
//	p, err := nxs.New(ctx, nxs.Config{Origin: "https://provider.example", StateDir: "nxs", Address: ":19133"})
//	...
//	l, err := nethernet.ListenConfig{}.Listen(p)
package nxs

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/df-mc/go-nethernet"
)

// Config configures a Provider.
type Config struct {
	// Origin is the HTTPS origin of the provider, such as https://provider.example.
	Origin string
	// StateDir is the directory holding the durable state of this instance, including its
	// machine key and admission keys. Each instance needs its own directory.
	StateDir string
	// Token is the bearer token used to register this instance. If empty, the instance is
	// registered anonymously with proof of work, if the provider allows it.
	Token string
	// Mode is the registration mode. It defaults to ModeAutomatic.
	Mode string
	// Label is an optional label for a new registration.
	Label string
	// Placement is the optional region and pool of the instance.
	Placement *Placement

	// Address is the UDP address that players connect to. It defaults to ":0", which
	// should only be used if the port is reachable through STUN mappings.
	Address string
	// Endpoints are the public UDP endpoints advertised to players. If empty, local and
	// STUN-mapped addresses of Address are advertised.
	Endpoints []netip.AddrPort
	// Capacity is the maximum number of players admitted. If zero, the maximum player
	// count of the listener is used.
	Capacity int
	// Build is an optional build identifier reported to the provider.
	Build string

	// WebSocket enables the WebSocket control transport if the provider advertises it.
	// Operations fall back to HTTPS while it is unavailable.
	WebSocket bool
	// AssistedJoins lets the provider forward the offers of players that cannot be
	// admitted statelessly. It requires the WebSocket control transport.
	AssistedJoins bool
	// Diagnostics lets the provider check the connectivity of the host with single
	// exchanges on the gameplay socket, which never reach the Listener.
	Diagnostics bool
	// GameOutcomes reports that the application calls GameJoined and GameRejected for
	// admitted connections.
	GameOutcomes bool

	// Log is used for logging. It defaults to [slog.Default].
	Log *slog.Logger
	// HTTPClient is used for provider requests. Redirects are always disabled.
	HTTPClient *http.Client
}

// Provider maintains the registration of a host with an NXS provider and admits
// connections routed to it. It implements [nethernet.Signaling].
type Provider struct {
	conf   Config
	log    *slog.Logger
	origin string
	client *client
	store  *store
	disc   *discovery
	key    *ecdsa.PrivateKey
	host   *host
	ws     *controlSocket

	ctx    context.Context
	cancel context.CancelCauseFunc
	// stop stops the background loop without closing the listener.
	stop    context.CancelFunc
	done    chan struct{}
	closing atomic.Bool
	once    sync.Once

	// opMu serializes provider operations and guards st and the state below.
	opMu             sync.Mutex
	st               *state
	profileRevision  string
	lastProfile      []byte
	outcomesReported bool
	clock            int64
	lastRecovery     time.Time
	appliedState     int64
	endpoints        endpointState

	mu            sync.Mutex
	status        *serverStatus
	events        []event
	readiness     Readiness
	registrations map[string]extension
	dirty         atomic.Bool

	// published and authority are snapshots used by assisted joins.
	published atomic.Pointer[[]candidate]
	authority atomic.Pointer[authority]
}

// New registers the host with the provider, or resumes its saved registration, and binds
// the gameplay socket. The Provider must be closed after use.
func New(ctx context.Context, conf Config) (*Provider, error) {
	origin, err := normalizeOrigin(conf.Origin)
	if err != nil {
		return nil, err
	}
	if conf.Log == nil {
		conf.Log = slog.Default()
	}
	if conf.Mode == "" {
		conf.Mode = ModeAutomatic
	}
	if conf.Address == "" {
		conf.Address = ":0"
	}
	if conf.AssistedJoins {
		conf.WebSocket = true
	}
	if conf.Placement != nil {
		if err := conf.Placement.validate(); err != nil {
			return nil, err
		}
	}
	if conf.Mode == ModeAttachInstance && (conf.Token == "" || conf.Placement == nil) {
		return nil, errors.New("nxs: attach-instance requires Token and Placement")
	}
	s, err := openStore(conf.StateDir)
	if err != nil {
		return nil, err
	}
	p := &Provider{
		conf:   conf,
		log:    conf.Log.With("src", "nxs"),
		origin: origin,
		client: newClient(origin, conf.HTTPClient),
		store:  s,
		done:   make(chan struct{}),
	}
	p.ctx, p.cancel = context.WithCancelCause(context.Background())
	if err := p.start(ctx); err != nil {
		p.cancel(err)
		p.ws.close()
		if p.host != nil {
			_ = p.host.close()
		}
		_ = s.close()
		return nil, err
	}
	return p, nil
}

func (p *Provider) start(ctx context.Context) error {
	st, err := p.store.load()
	if err != nil {
		return err
	}
	if st.Provider != "" && st.Provider != p.origin {
		return fmt.Errorf("nxs: state belongs to provider %s, use a separate StateDir", st.Provider)
	}
	p.st = st

	p.disc = &discovery{}
	if err := p.client.do(ctx, request{method: http.MethodGet, url: p.origin + discoveryPath}, p.disc); err != nil {
		return fmt.Errorf("nxs: discovery: %w", err)
	}
	scheme := schemeAnonymous
	if p.conf.Token != "" {
		scheme = schemeBearer
	}
	if err := p.disc.validate(p.origin, scheme, p.conf.Mode); err != nil {
		return fmt.Errorf("nxs: discovery: %w", err)
	}
	if p.conf.WebSocket {
		if p.ws, err = newControlSocket(p); err != nil {
			return err
		}
		if p.ws == nil && p.conf.AssistedJoins {
			p.log.Warn("provider does not advertise a WebSocket control transport, assisted joins are disabled")
		}
	}

	if st.PrivateKey == "" {
		key, err := generateMachineKey()
		if err != nil {
			return err
		}
		if st.PrivateKey, err = encodePrivateKey(key); err != nil {
			return err
		}
		st.Provider = p.origin
		if err := p.store.save(st); err != nil {
			return err
		}
	}
	if p.key, err = decodePrivateKey(st.PrivateKey); err != nil {
		return fmt.Errorf("nxs: decode machine key: %w", err)
	}
	if err := p.register(ctx); err != nil {
		return err
	}
	if err := p.startGeneration(); err != nil {
		return err
	}
	p.events = st.PendingEvents
	p.log.Info("registered with provider", "provider", p.origin, "instance", st.Registration.InstanceID, "publicAddress", st.Registration.PublicAddress)
	for name, ext := range p.registrations {
		p.log.Info("provider extension", "name", name, "data", string(ext.Data))
	}

	if p.host, err = newHost(p.conf.Address, p.conf.Capacity, p.log); err != nil {
		return err
	}
	p.host.report, p.host.changed = p.record, p.poke
	p.host.gameOutcomes = p.conf.GameOutcomes
	p.host.setKeys(st.keys())

	loop, stop := context.WithCancel(p.ctx)
	p.stop = stop
	go p.run(loop)
	return nil
}

// startGeneration resets the operational state after a completed registration or recovery.
// opMu must be held, or the Provider not yet running.
func (p *Provider) startGeneration() error {
	st := p.st
	// Completion starts a new generation, with sequencing starting at zero.
	st.Generation, st.Sequence = st.Registration.LeaseGeneration, 0
	if exts := st.Registration.Extensions; exts != nil {
		p.mu.Lock()
		p.registrations = exts
		p.mu.Unlock()
	}
	p.mu.Lock()
	p.readiness = st.Registration.Readiness
	p.mu.Unlock()
	p.profileRevision, p.lastProfile, p.outcomesReported = "", nil, false
	return p.store.save(st)
}

// poke requests an early heartbeat.
func (p *Provider) poke() { p.dirty.Store(true) }

// Readiness returns the latest readiness observation of the provider.
func (p *Provider) Readiness() Readiness {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.readiness
}

// PublicAddress returns the public address players may use to join, if the provider
// assigned one.
func (p *Provider) PublicAddress() string {
	p.opMu.Lock()
	defer p.opMu.Unlock()
	if p.st.Registration == nil {
		return ""
	}
	return p.st.Registration.PublicAddress
}

// Extensions returns the optional provider metadata returned with the registration, such
// as a link to claim the service. Its keys are reverse-DNS namespaces.
func (p *Provider) Extensions() map[string]json.RawMessage {
	p.mu.Lock()
	defer p.mu.Unlock()
	m := make(map[string]json.RawMessage, len(p.registrations))
	for name, ext := range p.registrations {
		m[name] = ext.Data
	}
	return m
}

// GameJoined reports that the player of an admitted connection joined the game. It must
// only be called if Config.GameOutcomes is set. conn is typically a gophertunnel
// minecraft.Conn or a nethernet.Conn.
func (p *Provider) GameJoined(conn interface{ RemoteAddr() net.Addr }) {
	p.host.gameOutcome(conn.RemoteAddr(), "ticket.game_joined", "")
}

// GameRejected reports that the game rejected the player of an admitted connection, with
// a short reason code. It must only be called if Config.GameOutcomes is set.
func (p *Provider) GameRejected(conn interface{ RemoteAddr() net.Addr }, reason string) {
	p.host.gameOutcome(conn.RemoteAddr(), "ticket.game_rejected", reason)
}

// Signal always returns an error, as players are signaled by the provider.
func (p *Provider) Signal(context.Context, *nethernet.Signal) error {
	return errors.New("nxs: signals are exchanged by the provider")
}

// Notify attaches a [nethernet.Listener] that admitted connections are delivered to.
func (p *Provider) Notify(n nethernet.Notifier) (stop func()) {
	a, ok := n.(admitter)
	if !ok {
		return func() {}
	}
	p.host.setListener(a)
	p.poke()
	return sync.OnceFunc(func() {
		p.host.clearListener(a)
		p.poke()
	})
}

// Context returns a context that is canceled when the Provider is closed.
func (p *Provider) Context() context.Context { return p.ctx }

// Credentials returns nil, as no ICE servers are used.
func (p *Provider) Credentials(context.Context) (*nethernet.Credentials, error) { return nil, nil }

// NetworkID returns the instance ID of the host.
func (p *Provider) NetworkID() string {
	p.opMu.Lock()
	defer p.opMu.Unlock()
	return p.st.Registration.InstanceID
}

// PongData updates the listing metadata reported to the provider from the RakNet-format
// pong data of the listener.
func (p *Provider) PongData(b []byte) {
	s, ok := parsePong(b)
	if !ok {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.status == nil || *p.status != *s {
		p.status = s
		p.poke()
	}
}

// Addr returns the local address of the gameplay socket.
func (p *Provider) Addr() net.Addr { return p.host.Addr() }

// Pause stops admitting players and reports this to the provider with the next heartbeat.
// Established connections and admissions already in progress are not affected.
func (p *Provider) Pause() {
	p.host.pause()
	p.poke()
}

// Resume admits players again after Pause.
func (p *Provider) Resume() {
	p.host.resume()
	p.poke()
}

// Close stops accepting players, reports this to the provider and closes the gameplay
// socket. Established connections are closed with it.
func (p *Provider) Close() error {
	var err error
	p.once.Do(func() {
		p.closing.Store(true)
		p.authority.Store(nil)
		p.host.stop()
		p.stop()
		<-p.done
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, _, e := p.heartbeat(ctx); e != nil {
			p.log.Debug("final heartbeat failed", "error", e)
		}
		_ = p.flush(ctx)
		err = p.shutdown()
	})
	return err
}

// Deregister permanently ends the registration of this instance and closes the Provider,
// even if deregistration fails. A later Provider using the same StateDir registers as a
// new instance.
func (p *Provider) Deregister(ctx context.Context) error {
	err := net.ErrClosed
	p.once.Do(func() {
		p.closing.Store(true)
		p.host.stop()
		p.stop()
		<-p.done
		p.opMu.Lock()
		if err = p.signed(ctx, "deregister", struct{}{}, nil, 3, 15*time.Second); err == nil {
			err = p.store.save(&state{Version: stateVersion})
		} else {
			err = fmt.Errorf("nxs: deregister: %w", err)
		}
		p.opMu.Unlock()
		err = errors.Join(err, p.shutdown())
	})
	return err
}

func (p *Provider) shutdown() error {
	p.ws.close()
	p.cancel(net.ErrClosed)
	return errors.Join(p.host.close(), p.store.close())
}
