package network

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	TypeUnix = "unix"

	UNIXDefaultKeepAliveInterval = time.Second * 15
)

// ============================== Server ==============================

func socketFileStat(path string) (string, os.FileInfo, error) {
	var err error
	path, err = filepath.Abs(strings.TrimSpace(path))
	if err != nil {
		return "", nil, err
	}
	var info os.FileInfo
	if info, err = os.Stat(path); err != nil {
		return path, nil, err
	}
	return path, info, nil
}

func removeSocketFile(path string) error {
	if fullPath, fileInfo, err := socketFileStat(path); err == nil && fileInfo != nil && !fileInfo.IsDir() {
		if err = os.Remove(fullPath); err != nil {
			return err
		}
	}
	return nil
}

type UnixServerConfig struct {
	RemoveBeforeServe bool     `json:"remove_before_serve"`
	EnableKeepAlive   bool     `json:"enable_keep_alive"`
	KeepAliveInterval duration `json:"keep_alive_interval"`
}

func (tc *UnixServerConfig) applyToListenConfig(lc *net.ListenConfig) error {
	if tc.EnableKeepAlive {
		lc.KeepAlive = fallback(tc.KeepAliveInterval.Duration(), UNIXDefaultKeepAliveInterval)
	} else {
		lc.KeepAlive = -1
	}
	return nil
}

type unixServer struct {
	config UnixServerConfig
	addr   Addr
}

func (u *unixServer) Type() string { return TypeUnix }

func (u *unixServer) Addr() Addr { return u.addr }

func (u *unixServer) Config() interface{} { return &u.config }

func (u *unixServer) Upstream() Server { return nil }

func (u *unixServer) ListenContext(ctx context.Context) (listener Listener, err error) {
	var listenConfig = &net.ListenConfig{}
	var config = u.config
	if err = config.applyToListenConfig(listenConfig); err != nil {
		return nil, err
	}
	var netListener net.Listener
	if u.config.RemoveBeforeServe {
		if err = removeSocketFile(u.addr.String()); err != nil {
			return nil, err
		}
	}
	if netListener, err = listenConfig.Listen(ctx, u.addr.Network(), u.addr.String()); err != nil {
		return nil, err
	}
	return &unixListener{server: u, Listener: netListener}, nil
}

func (u *unixServer) ListenPacket(ctx context.Context) (packetConn PacketConn, err error) {
	var listenConfig = &net.ListenConfig{}
	var config = u.config
	if err = config.applyToListenConfig(listenConfig); err != nil {
		return nil, err
	}
	var netPacketConn net.PacketConn
	if u.config.RemoveBeforeServe {
		if err = removeSocketFile(u.addr.String()); err != nil {
			return nil, err
		}
	}
	if netPacketConn, err = listenConfig.ListenPacket(ctx, u.addr.Network(), u.addr.String()); err != nil {
		return nil, err
	}
	if netUdpConn, ok := netPacketConn.(*net.UnixConn); !ok {
		return nil, ErrUnsupportedProtocol
	} else {
		return &unixPacketListener{server: u, UnixConn: netUdpConn}, nil
	}
}

type unixListener struct {
	server *unixServer
	net.Listener
}

func (ul *unixListener) Addr() net.Addr { return &ul.server.addr }

func (ul *unixListener) Server() Server { return ul.server }

func (ul *unixListener) Underlying() interface{} { return ul.Listener }

type unixPacketListener struct {
	server *unixServer
	*net.UnixConn
}

func (ul *unixPacketListener) Addr() net.Addr { return &ul.server.addr }

func (ul *unixPacketListener) Underlying() interface{} { return ul.UnixConn }

// ============================== Client ==============================

type UnixClientConfig struct {
	RemoveBeforeServe bool     `json:"remove_before_serve"`
	EnableKeepAlive   bool     `json:"enable_keep_alive"`
	KeepAliveInterval duration `json:"keep_alive_interval"`
	StackFallbackGap  duration `json:"stack_fallback_gap"`
	TimeoutDuration   duration `json:"dial_timeout"`
	LocalNetwork      string   `json:"local_network"`
	LocalAddress      string   `json:"local_address"`
}

func (uc *UnixClientConfig) applyToDialer(dialer *net.Dialer) error {
	if uc.EnableKeepAlive {
		dialer.KeepAlive = uc.KeepAliveInterval.Duration()
	} else {
		dialer.KeepAlive = -1
	}
	dialer.Timeout = uc.TimeoutDuration.Duration()
	dialer.FallbackDelay = uc.StackFallbackGap.Duration()
	if uc.LocalAddress != "" {
		dialer.LocalAddr = NewAddr(fallback(uc.LocalNetwork, TypeUnix), uc.LocalAddress)
	}
	return nil
}

func (uc *UnixClientConfig) applyToListenConfig(lc *net.ListenConfig) error {
	if uc.EnableKeepAlive {
		lc.KeepAlive = uc.KeepAliveInterval.Duration()
	} else {
		lc.KeepAlive = -1
	}
	return nil
}

type unixClient struct {
	config UnixClientConfig
}

func (u *unixClient) Type() string { return TypeUnix }

func (u *unixClient) Config() interface{} { return &u.config }

func (u *unixClient) Upstream() Client { return nil }

func (u *unixClient) Dialer(context.Context) (Dialer, error) {
	var netDialer = &net.Dialer{}
	if err := u.config.applyToDialer(netDialer); err != nil {
		return nil, err
	}
	return &unixDialer{Dialer: netDialer}, nil
}

func (u *unixClient) Resolve(network, address string) (net.Addr, error) {
	return net.ResolveUnixAddr(network, address)
}

func (u *unixClient) ListenPacket(ctx context.Context) (packetConn PacketConn, err error) {
	var listenConfig = &net.ListenConfig{}
	var config = u.config
	if err = config.applyToListenConfig(listenConfig); err != nil {
		return nil, err
	}
	var localAddr net.Addr
	var localNetwork = u.config.LocalNetwork
	if localNetwork == "" {
		localNetwork = TypeUnix
	}
	if u.config.LocalAddress == "" {
		return nil, fmt.Errorf("`local_address` not configured")
	} else if localAddr, err = u.Resolve(localNetwork, u.config.LocalAddress); err != nil {
		return nil, err
	}
	var netPacketConn net.PacketConn
	if u.config.RemoveBeforeServe {
		if err = removeSocketFile(localAddr.String()); err != nil {
			return nil, err
		}
	}
	if netPacketConn, err = listenConfig.ListenPacket(ctx, localAddr.Network(), localAddr.String()); err != nil {
		return nil, err
	}
	if netUdpConn, ok := netPacketConn.(*net.UnixConn); !ok {
		return nil, ErrUnsupportedProtocol
	} else {
		return &unixPacketListener{server: nil, UnixConn: netUdpConn}, nil
	}
}

type unixDialer struct {
	client *unixClient
	*net.Dialer
}

func (ud *unixDialer) Client() Client { return ud.client }

func (ud *unixDialer) Underlying() interface{} { return ud.Dialer }
