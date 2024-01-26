package network

import (
	"context"
	"net"
	"time"
)

const (
	TypeUDP = "udp"

	UDPDefaultKeepAliveInterval = time.Second * 15
)

// ============================== Server ==============================

type UDPServerConfig struct {
	EnableKeepAlive   bool     `json:"enable_keep_alive"`
	KeepAliveInterval duration `json:"keep_alive_interval"`
}

func (tc *UDPServerConfig) applyToListenConfig(lc *net.ListenConfig) error {
	if tc.EnableKeepAlive {
		lc.KeepAlive = fallback(tc.KeepAliveInterval.Duration(), UDPDefaultKeepAliveInterval)
	} else {
		lc.KeepAlive = -1
	}
	return nil
}

type udpServer struct {
	config UDPServerConfig
	addr   Addr
}

func (u *udpServer) Type() string { return TypeUDP }

func (u *udpServer) Addr() Addr { return u.addr }

func (u *udpServer) Config() interface{} { return &u.config }

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

func (ul *udpPacketListener) Underlying() interface{} { return ul.UDPConn }

// ============================== Client ==============================

type UDPClientConfig struct {
	EnableKeepAlive   bool     `json:"enable_keep_alive"`
	KeepAliveInterval duration `json:"keep_alive_interval"`
	StackFallbackGap  duration `json:"stack_fallback_gap"`
	TimeoutDuration   duration `json:"dial_timeout"`
	LocalNetwork      string   `json:"local_network"`
	LocalAddress      string   `json:"local_address"`
}

func (uc *UDPClientConfig) applyToDialer(dialer *net.Dialer) error {
	if uc.EnableKeepAlive {
		dialer.KeepAlive = uc.KeepAliveInterval.Duration()
	} else {
		dialer.KeepAlive = -1
	}
	dialer.Timeout = uc.TimeoutDuration.Duration()
	dialer.FallbackDelay = uc.StackFallbackGap.Duration()
	if uc.LocalAddress != "" {
		dialer.LocalAddr = NewAddr(fallback(uc.LocalNetwork, TypeUDP), uc.LocalAddress)
	}
	return nil
}

func (uc *UDPClientConfig) applyToListenConfig(lc *net.ListenConfig) error {
	if uc.EnableKeepAlive {
		lc.KeepAlive = uc.KeepAliveInterval.Duration()
	} else {
		lc.KeepAlive = -1
	}
	return nil
}

type udpClient struct {
	config UDPClientConfig
}

func (u *udpClient) Type() string { return TypeUDP }

func (u *udpClient) Config() interface{} { return &u.config }

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

func (ud *udpDialer) Underlying() interface{} { return ud.Dialer }
