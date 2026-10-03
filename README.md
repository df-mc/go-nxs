# go-nxs

A Go implementation of [NetherNet External Signaling](https://github.com/CloudburstMC/Network/blob/nethernet/docs/external-signaling/README.md)
(NXS) for hosts, built on [go-nethernet](https://github.com/df-mc/go-nethernet). NXS lets a
signaling provider such as [Warden](https://warden.cloud) handle HTTPS signaling with players,
while game traffic flows directly between players and the host.

The provider answers each player with a short-lived NXS1 token in the ICE ufrag. The host
validates the token from the player's first STUN request and admits the connection into a
`nethernet.Listener`, without seeing the player's SDP.

## Usage

`nxs.Provider` implements `nethernet.Signaling`:

```go
p, err := nxs.New(ctx, nxs.Config{
	Origin:   "https://provider.example",
	Token:    token,      // Optional: anonymous proof of work is used otherwise.
	StateDir: "nxs",      // One directory per instance. It holds secrets.
	Address:  ":19133",   // The UDP port players connect to.
})
if err != nil {
	panic(err)
}
defer p.Close()

l, err := nethernet.ListenConfig{}.Listen(p)
```

With gophertunnel, pass the Provider as `minecraft.NetherNet{Signaling: p}` to
`minecraft.ListenConfig.ListenNetwork`. After login, gophertunnel checks the login
identity against the admission through `nethernet.Conn.VerifyPublicKey`. See
[examples/gophertunnel](examples/gophertunnel).

The host advertises its local addresses and STUN mappings of `Address`, and withholds
public endpoints that fail the regional checks of the provider. Set `Config.Endpoints` if
players must reach it through a forwarded port instead.

### Options

- `WebSocket` carries operations over the WebSocket control transport of the provider,
  falling back to HTTPS.
- `AssistedJoins` lets the provider forward the offers of players over the WebSocket, for
  players that cannot be admitted statelessly.
- `Diagnostics` answers the connectivity checks of the provider on the gameplay socket.
  They never reach the Listener.
- `GameOutcomes` reports that the application calls `GameJoined` and `GameRejected`.

`Pause` and `Resume` stop and resume admitting players without closing established
connections.

`RotateAdmissionKey`, `RotateMachineKey`, `Deregister` and `ExtensionRequest` expose
the remaining operations. Registrations are recovered in a new generation after a
restart, or when the provider fences the current one.
