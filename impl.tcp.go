package network

import (
	"context"
	"net"
)

const TypeTCP = "tcp"

// ============================== Server ==============================

type TCPServerConfig struct {
	EnableNoDelay     bool     `json:"enable_no_delay" yaml:"enable_no_delay"`
	KeepAliveInterval Duration `json:"keep_alive_interval" yaml:"keep_alive_interval"`
}

func (tc *TCPServerConfig) applyToListenConfig(lc *net.ListenConfig) error {
	if keepAliveDuration := tc.KeepAliveInterval.Duration(); keepAliveDuration > 0 {
		lc.KeepAlive = keepAliveDuration // enable
	} else if keepAliveDuration < 0 {
		lc.KeepAlive = -1 // disable
	}
	return nil
}

func NewTCPServer(cfg TCPServerConfig, addr string) Server {
	return &tcpServer{config: cfg, addr: NewAddr(TypeTCP, addr)}
}

type tcpServer struct {
	config TCPServerConfig
	addr   Addr
}

func (t *tcpServer) Type() string { return TypeTCP }

func (t *tcpServer) Addr() Addr { return t.addr }

func (t *tcpServer) Config() any { return &t.config }

func (t *tcpServer) Upstream() Server { return nil }

func (t *tcpServer) ListenContext(ctx context.Context) (listener Listener, err error) {
	var listenConfig = &net.ListenConfig{}
	var config = t.config
	if err = config.applyToListenConfig(listenConfig); err != nil {
		return nil, err
	}
	var netListener net.Listener
	if netListener, err = listenConfig.Listen(ctx, t.addr.Network(), t.addr.String()); err != nil {
		return nil, err
	}
	return &tcpListener{server: t, Listener: netListener}, nil
}

func (t *tcpServer) ListenPacket(context.Context) (packetConn PacketConn, err error) {
	return nil, ErrUnsupportedProtocol
}

type tcpListener struct {
	server *tcpServer
	net.Listener
}

func (tl *tcpListener) Server() Server { return tl.server }

func (tl *tcpListener) Underlying() any { return tl.Listener }

func (tl *tcpListener) Accept() (conn net.Conn, err error) {
	conn, err = tl.Listener.Accept()
	if err == nil && conn != nil {
		if err = tl.connInit(conn); err != nil {
			return nil, err
		}
	}
	return conn, err
}

func (tl *tcpListener) connInit(conn net.Conn) (err error) {
	if tcpConn, ok := conn.(*net.TCPConn); ok && tl.server != nil && tl.server.config.EnableNoDelay {
		if err = tcpConn.SetNoDelay(tl.server.config.EnableNoDelay); err != nil {
			return err
		}
	}
	return nil
}

// ============================== Client ==============================

type TCPClientConfig struct {
	EnableNoDelay     bool     `json:"enable_no_delay" yaml:"enable_no_delay"`
	KeepAliveInterval Duration `json:"keep_alive_interval" yaml:"keep_alive_interval"`
	StackFallbackGap  Duration `json:"stack_fallback_gap" yaml:"stack_fallback_gap"`
	TimeoutDuration   Duration `json:"dial_timeout" yaml:"dial_timeout"`
	LocalNetwork      string   `json:"local_network" yaml:"local_network"`
	LocalAddress      string   `json:"local_address" yaml:"local_address"`
}

func (tc *TCPClientConfig) applyToDialer(dialer *net.Dialer) error {
	if keepAliveDuration := tc.KeepAliveInterval.Duration(); keepAliveDuration > 0 {
		dialer.KeepAlive = keepAliveDuration // enable
	} else if keepAliveDuration < 0 {
		dialer.KeepAlive = -1 // disable
	}
	dialer.Timeout = tc.TimeoutDuration.Duration()
	dialer.FallbackDelay = tc.StackFallbackGap.Duration()
	if tc.LocalAddress != "" {
		dialer.LocalAddr = NewAddr(fallback(tc.LocalNetwork, TypeTCP), tc.LocalAddress)
	}
	return nil
}

func NewTCPClient(cfg TCPClientConfig) Client {
	return &tcpClient{config: cfg}
}

type tcpClient struct {
	config TCPClientConfig
}

func (t *tcpClient) Type() string { return TypeTCP }

func (t *tcpClient) Config() any { return &t.config }

func (t *tcpClient) Upstream() Client { return nil }

func (t *tcpClient) Dialer(context.Context) (Dialer, error) {
	var netDialer = &net.Dialer{}
	if err := t.config.applyToDialer(netDialer); err != nil {
		return nil, err
	}
	return &tcpDialer{client: t, Dialer: netDialer}, nil
}

func (t *tcpClient) Resolve(network, address string) (net.Addr, error) {
	return net.ResolveTCPAddr(network, address)
}

type tcpDialer struct {
	client *tcpClient
	*net.Dialer
}

func (td *tcpDialer) Client() Client { return td.client }

func (td *tcpDialer) Underlying() any { return td.Dialer }

func (td *tcpDialer) Dial(network string, address string) (conn net.Conn, err error) {
	conn, err = td.Dialer.Dial(network, address)
	if err == nil && conn != nil {
		if err = td.connInit(conn); err != nil {
			return nil, err
		}
	}
	return conn, err
}

func (td *tcpDialer) DialContext(ctx context.Context, network string, address string) (conn net.Conn, err error) {
	conn, err = td.Dialer.DialContext(ctx, network, address)
	if err == nil && conn != nil {
		if err = td.connInit(conn); err != nil {
			return nil, err
		}
	}
	return conn, err
}

func (td *tcpDialer) connInit(conn net.Conn) (err error) {
	if tcpConn, ok := conn.(*net.TCPConn); ok && td.client != nil && td.client.config.EnableNoDelay {
		if err = tcpConn.SetNoDelay(td.client.config.EnableNoDelay); err != nil {
			return err
		}
	}
	return nil
}
