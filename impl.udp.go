package network

import (
	"context"
	"net"
)

const TypeUDP = "udp"

// ============================== Server ==============================

type UDPServerConfig struct {
	KeepAliveInterval Duration `json:"keep_alive_interval"`
}

func (tc *UDPServerConfig) applyToListenConfig(lc *net.ListenConfig) error {
	if keepAliveDuration := tc.KeepAliveInterval.Duration(); keepAliveDuration > 0 {
		lc.KeepAlive = keepAliveDuration // enable
	} else if keepAliveDuration < 0 {
		lc.KeepAlive = -1 // disable
	}
	return nil
}

func NewUDPServer(cfg UDPServerConfig, addr string) Server {
	return &udpServer{config: cfg, addr: NewAddr(TypeUDP, addr)}
}

type udpServer struct {
	config UDPServerConfig
	addr   Addr
}

func (u *udpServer) Type() string { return TypeUDP }

func (u *udpServer) Addr() Addr { return u.addr }

func (u *udpServer) Config() any { return &u.config }

func (u *udpServer) Upstream() Server { return nil }

func (u *udpServer) ListenContext(_ context.Context) (_ Listener, err error) {
	return nil, ErrUnsupportedProtocol
}

func (u *udpServer) ListenPacket(ctx context.Context) (packetConn PacketConn, err error) {
	var listenConfig = &net.ListenConfig{}
	var config = u.config
	if err = config.applyToListenConfig(listenConfig); err != nil {
		return nil, err
	}
	var netPacketConn net.PacketConn
	if netPacketConn, err = listenConfig.ListenPacket(ctx, u.addr.Network(), u.addr.String()); err != nil {
		return nil, err
	}
	if netUdpConn, ok := netPacketConn.(*net.UDPConn); !ok {
		return nil, ErrUnsupportedProtocol
	} else {
		return &udpPacketListener{server: u, UDPConn: netUdpConn}, nil
	}
}

type udpPacketListener struct {
	server *udpServer
	*net.UDPConn
}

func (ul *udpPacketListener) Addr() net.Addr { return &ul.server.addr }

func (ul *udpPacketListener) Underlying() any { return ul.UDPConn }

// ============================== Client ==============================

type UDPClientConfig struct {
	KeepAliveInterval Duration `json:"keep_alive_interval"`
	StackFallbackGap  Duration `json:"stack_fallback_gap"`
	TimeoutDuration   Duration `json:"dial_timeout"`
	LocalNetwork      string   `json:"local_network"`
	LocalAddress      string   `json:"local_address"`
}

func (uc *UDPClientConfig) applyToDialer(dialer *net.Dialer) error {
	if keepAliveDuration := uc.KeepAliveInterval.Duration(); keepAliveDuration > 0 {
		dialer.KeepAlive = keepAliveDuration // enable
	} else if keepAliveDuration < 0 {
		dialer.KeepAlive = -1 // disable
	}
	dialer.Timeout = uc.TimeoutDuration.Duration()
	dialer.FallbackDelay = uc.StackFallbackGap.Duration()
	if uc.LocalAddress != "" {
		dialer.LocalAddr = NewAddr(fallback(uc.LocalNetwork, TypeUDP), uc.LocalAddress)
	}
	return nil
}

func (uc *UDPClientConfig) applyToListenConfig(lc *net.ListenConfig) error {
	if keepAliveDuration := uc.KeepAliveInterval.Duration(); keepAliveDuration > 0 {
		lc.KeepAlive = keepAliveDuration // enable
	} else if keepAliveDuration < 0 {
		lc.KeepAlive = -1 // disable
	}
	return nil
}

type udpClient struct {
	config UDPClientConfig
}

func (u *udpClient) Type() string { return TypeUDP }

func (u *udpClient) Config() any { return &u.config }

func (u *udpClient) Upstream() Client { return nil }

func (u *udpClient) Dialer(context.Context) (Dialer, error) {
	var netDialer = &net.Dialer{}
	if err := u.config.applyToDialer(netDialer); err != nil {
		return nil, err
	}
	return &udpDialer{Dialer: netDialer}, nil
}

func (u *udpClient) Resolve(network, address string) (net.Addr, error) {
	return net.ResolveUDPAddr(network, address)
}

func (u *udpClient) ListenPacket(ctx context.Context) (packetConn PacketConn, err error) {
	var listenConfig = &net.ListenConfig{}
	var config = u.config
	if err = config.applyToListenConfig(listenConfig); err != nil {
		return nil, err
	}
	var localAddr net.Addr
	var localNetwork = u.config.LocalNetwork
	if localNetwork == "" {
		localNetwork = TypeUDP
	}
	if localAddr, err = u.Resolve(localNetwork, u.config.LocalAddress); err != nil {
		return nil, err
	}
	var netPacketConn net.PacketConn
	if netPacketConn, err = listenConfig.ListenPacket(ctx, localAddr.Network(), localAddr.String()); err != nil {
		return nil, err
	}
	if netUdpConn, ok := netPacketConn.(*net.UDPConn); !ok {
		return nil, ErrUnsupportedProtocol
	} else {
		return &udpPacketListener{server: nil, UDPConn: netUdpConn}, nil
	}
}

type udpDialer struct {
	client *udpClient
	*net.Dialer
}

func (ud *udpDialer) Client() Client { return ud.client }

func (ud *udpDialer) Underlying() any { return ud.Dialer }
