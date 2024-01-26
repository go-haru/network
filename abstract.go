package network

import (
	"context"
	"errors"
	"io"
	"net"
)

var (
	ErrUnsupportedProtocol   = errors.New("unsupported network")
	ErrUnsupportedUpstream   = errors.New("unsupported upstream")
	ErrInvalidProtocolFormat = errors.New("invalid protocol format")
)

type Addr struct {
	NetworkStr string `json:"network"`
	AddressStr string `json:"address"`
}

func NewAddr(network, address string) Addr { return Addr{network, address} }

func (a Addr) Network() string { return a.NetworkStr }

func (a Addr) String() string { return a.AddressStr }

type Server interface {
	Type() string
	Addr() Addr
	Config() interface{}
	Upstream() Server
	ListenPacket(ctx context.Context) (packetConn PacketConn, err error)
	ListenContext(ctx context.Context) (listener Listener, err error)
}

type Listener interface {
	Server() Server
	Underlying() interface{}
	net.Listener
}

type SubListener interface {
	Listener
	Upstream() Listener
}

type ListenerContext interface {
	Listener
	AcceptContext(ctx context.Context) (net.Conn, error)
}

type PacketListener interface {
	ListenPacket(ctx context.Context) (packetConn PacketConn, err error)
}

type PacketConn interface {
	Underlying() interface{}
	net.PacketConn
}

type ListenerMultiplexed interface {
	Listener
	AcceptMux() (Listener, error)
	AcceptMuxContext(ctx context.Context) (Listener, error)
}

type Client interface {
	Type() string
	Config() interface{}
	Upstream() Client
	Dialer(ctx context.Context) (Dialer, error)
	Resolve(network, address string) (net.Addr, error)
}

type NativeDialer interface {
	Dial(network string, address string) (net.Conn, error)
	DialContext(ctx context.Context, network string, address string) (net.Conn, error)
}

type Dialer interface {
	Client() Client
	Underlying() interface{}
	NativeDialer
}

type SubDialer interface {
	Dialer
	Upstream() Dialer
}

type DialerCloser interface {
	Dialer
	io.Closer
}

type DialerMultiplexed interface {
	Dialer
	DialMux(network string, address string) (DialerCloser, error)
	DialMuxContext(ctx context.Context, network string, address string) (DialerCloser, error)
}
