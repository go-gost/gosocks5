# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Verify

```bash
go build ./...   # Build the library
go vet ./...     # Vet all packages
```

There are no tests in this module. Building + vetting is the verification path.

## Architecture

This is a pure SOCKS5 protocol library (RFC 1928 + RFC 1929). It has zero external dependencies.

### Layer model

```
┌─────────────────────────────────┐
│  client/   │   server/          │  ← High-level: Dialer + Server
│  Dial()    │   Server.Serve()   │
├─────────────────────────────────┤
│  conn.go                       │  ← Conn: lazy handshake wrapper
├─────────────────────────────────┤
│  socks5.go                     │  ← Wire protocol: Addr, Request,
│                                 │     Reply, UDPHeader, UDPDatagram
└─────────────────────────────────┘
```

### `socks5.go` — Wire protocol

Contains all protocol constants, address types (`Addr`, `AddrIPv4`, `AddrDomain`, `AddrIPv6`), and wire-format types:

- **`Addr`** — Parses/renders the SOCKS5 address format (IPv4, domain, IPv6). Constructor: `NewAddr(host:port string)`. Methods: `ReadFrom`, `WriteTo`, `String`, `Decode`.
- **`Request`** — `{Ver, Cmd, Addr}`. Constructor: `NewRequest(cmd, addr)`. Read/write via `ReadRequest(r)` / `Write(w)`.
- **`Reply`** — `{Ver, Rep, Addr}`. Constructor: `NewReply(rep, addr)`. Read/write via `ReadReply(r)` / `Write(w)`.
- **`UserPassRequest/Response`** — Username/password auth sub-negotiation (RFC 1929).
- **`UDPHeader`** — `{Rsv, Frag, Addr}` wrapping a UDP datagram. Must nil-guard `Addr` before use.
- **`UDPDatagram`** — `{Header, Data}`.

Key sentinel errors: `ErrBadVersion`, `ErrBadFormat`, `ErrBadMethod`, `ErrBadAddress`, `ErrAuthFailure`, `ErrUnrecognizedAddrType`.

### `conn.go` — Lazy handshake wrapper

`Conn` wraps a `net.Conn` and transparently performs the SOCKS5 method negotiation on first `Read` or `Write` call — callers don't need to explicitly handshake. It implements `net.Conn`.

Twist: `Handleshake()` (note the intentional misspelling) is a public method. It's idempotent and concurrency-safe (via `sync.Mutex`). Once handshaked, it caches the result and replays any error on subsequent calls.

- `ClientConn(net.Conn, Selector)` — Wraps for client-side handshake
- `ServerConn(net.Conn, Selector)` — Wraps for server-side handshake

On the client side, `OnSelected` returns a replacement `net.Conn` — this allows user/pass auth to wrap the connection if needed.

### `Selector` interface (defined in `conn.go`, not `socks5.go`)

```go
type Selector interface {
    Methods() []uint8                    // supported auth methods
    Select(methods ...uint8) (method uint8)  // server: pick one from client's offer
    OnSelected(method uint8, conn net.Conn) (string, net.Conn, error) // execute selected auth
}
```

This is the auth plugin point. Both sides implement it:
- **Client** (`client/selector.go`): `Select` is a no-op (server chooses). `OnSelected` sends user/pass credentials if `MethodUserPass` was chosen.
- **Server** (`server/selector.go`): `Select` picks from the client's offered methods. If users are configured, `MethodUserPass` is mandatory; returns `MethodNoAcceptable` if client didn't offer it. `OnSelected` validates credentials against the configured user list.

### `client/` — Client dialer

- `Dial(addr, options...)` — TCP dial + SOCKS5 handshake, returns a handshaked `*gosocks5.Conn` (which is a `net.Conn`).
- `DialContext(ctx, addr, options...)` — Context-aware variant.
- Options: `SelectorDialOption`, `TimeoutDialOption`.

`DefaultSelector` supports only `MethodNoAuth` unless overridden via `NewClientSelector(user, methods...)`.

### `server/` — Server

- `Server` struct wraps a `net.Listener`.
- `Server.Serve(handler)` — Accept loop with exponential backoff for temporary errors, then spawns `handler.Handle(conn)` per connection.
- `Handler` interface: `Handle(conn net.Conn) error`.
- `DefaultHandler` (`server/handler.go`): handles `CmdConnect` (TCP relay) and `CmdBind` (active-mode bind). Uses a `sync.Pool` buffer (`trPool`, 1500-byte buffers) for bidirectional copy. The `transport()` function uses a buffered error channel (`cap=2`) that both relay goroutines write to — the second is intentionally unconsumed to prevent goroutine leaks.

## Key conventions

- **No external dependencies** — the go.mod declares zero requires. This is intentional.
- **`trPool` buffer pool** — 1500 bytes (Ethernet MTU-sized). Used by `io.CopyBuffer` in the relay.
- **`toSocksAddr`** — Converts `net.Addr` to `gosocks5.Addr`, with IPv6 detection via `net.ParseIP` + `To4()`.
- **Nil-guard `Addr`** — `UDPHeader.Addr` is a pointer and may be nil. All methods (`ReadFrom`, `WriteTo`, `String`) must nil-guard it.
