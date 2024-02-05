# Network

[![Go Reference](https://pkg.go.dev/badge/github.com/go-haru/network.svg)](https://pkg.go.dev/github.com/go-haru/network)
[![License](https://img.shields.io/github/license/go-haru/network)](./LICENSE)
[![Release](https://img.shields.io/github/v/release/go-haru/network.svg?style=flat-square)](https://github.com/go-haru/network/releases)
[![Go Test](https://github.com/go-haru/network/actions/workflows/go.yml/badge.svg)](https://github.com/go-haru/network/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/go-haru/network)](https://goreportcard.com/report/github.com/go-haru/network)

This package provides factory and wrapper of native net listener and dialer for configuration maintaining and continuous portability.

## Concepts

### Address

Methods:
- `Network() string` get network type.
- `String() string` get real address.

### Server
Maintains a copy of Listener config, including desired address & port. New listener can be easily created for error retrying or dynamic loading.

Methods:
- `Type() string` - Get network type
- `Addr() Addr` - Get the listening(local) address
- `Config() any` - Get the listener's configuration
- `Upstream() Server` - Get the upstream wrapped server
- `ListenPacket()`, `ListenContext()` - Create listener

By calling `ListenPacket` or `ListenContext`, we can get stateless or stateful listener as following.

### Listener

Wrapper of `net.Listener`, typically for stateful sessions like tcp connection. you can directly call its `Accept()` for handling incoming connection.

```go
Accept() (Conn, error)
```

Cancelable accept operation may be provided by some external package, like `quic`, which implements `ListenerContext`:

```go
AcceptContext(ctx context.Context) (net.Conn, error)
```

if one Listener is built on top of another Listener, like `tls`, it may implement `SubListener`, which provide method to get upstream Listener:

```go
Upstream() Listener
```

Underlying object and parent server is available through both interface's `Underlying()` and `Server()` method.

```go
Underlying() any
Server() Server
```

### PacketListener

Since stateless connection has no session concept, to maintain consistency with the stateful listener creation process, here made this interface aliasing `Server`. Call `ListenPacket` to execute real operation.

```go
ListenPacket(ctx context.Context) (packetConn PacketConn, err error)
```

### Client
Like the `Server` interface, Maintains a copy of Dialer config, but address is not included. Though `Dialer` can be easily created, it's recommend to limit dialer amount for multiplexed connection.

Methods:
- `Type() string` - Get network type
- `Config() any` - Get the dialer's configuration
- `Upstream() Client` - Get the upstream wrapped dialer
- `Dialer(ctx context.Context) (Dialer, error)` - Create Dialer
- `Resolve(network, address string) (net.Addr, error)`- Parse target address

### Dialer

Abstraction of native `*net.Dialer`, with parent client and underlying provided.

- `Client() Client`
- `Underlying() any`
- `Dial(network string, address string) (net.Conn, error)`
- `DialContext(ctx context.Context, network string, address string) (net.Conn, error)`

### Multiplexing

For some protocol like QUIC, multiple logical connection on top of one physical connection, the `Listener` and `Dialer` can be asserted to following for enabling Multiplexing.

**ListenerMultiplexed**
- `Listener`
- `AcceptMux() (Listener, error)`
- `AcceptMuxContext(ctx context.Context) (Listener, error)`


**DialerMultiplexed**
- `Dialer`
- `DialMux(network string, address string) (DialerCloser, error)`
- `DialMuxContext(ctx context.Context, network string, address string) (DialerCloser, error)`


## Contributing

For convenience of PM, please commit all issue to [Document Repo](https://github.com/go-haru/go-haru/issues).

## License

This project is licensed under the `Apache License Version 2.0`.

Use and contributions signify your agreement to honor the terms of this [LICENSE](./LICENSE).

Commercial support or licensing is conditionally available through organization email.
