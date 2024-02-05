package network

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strings"
)

const TypeTls = "tls"

type X509Cert struct {
	Cert     string `json:"cert"`
	CertPath string `json:"cert_path"`
}

func (c *X509Cert) BuildX509Certificate() (certs []*x509.Certificate, err error) {
	var pemData []byte
	if c.Cert != "" {
		pemData = []byte(c.Cert)
	} else if c.CertPath == "" {
		return nil, fmt.Errorf("undefined certificate pem file path")
	} else if pemData, err = os.ReadFile(c.CertPath); err != nil {
		return nil, fmt.Errorf("cant open certificate pem file: %w, path: %q", err, c.CertPath)
	}
	var block *pem.Block
	for len(pemData) > 0 {
		block, pemData = pem.Decode(pemData)
		if block == nil {
			break
		}
		var cert *x509.Certificate
		if cert, err = x509.ParseCertificate(block.Bytes); err != nil {
			return nil, fmt.Errorf("invalid certificate file: %w, path: %q", err, c.CertPath)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no valid cert content")
	}
	return certs, nil
}

type X509CertKeyPair struct {
	Cert     string `json:"cert"`
	CertPath string `json:"cert_path"`
	Key      string `json:"key"`
	KeyPath  string `json:"key_path"`
}

func (c *X509CertKeyPair) BuildTLSCertificate() (cert tls.Certificate, err error) {
	var certContent []byte
	if c.Cert != "" {
		certContent = []byte(strings.TrimSpace(c.Cert))
	} else if c.CertPath == "" {
		return cert, fmt.Errorf("undefined certificate pem file path")
	} else if certContent, err = os.ReadFile(c.CertPath); err != nil {
		return cert, fmt.Errorf("cant open certificate pem file: %w, path: %q", err, c.CertPath)
	}
	var keyContent []byte
	if c.Key != "" {
		keyContent = []byte(strings.TrimSpace(c.Key))
	} else if c.KeyPath == "" {
		return cert, fmt.Errorf("undefined privateKey pem file path")
	} else if keyContent, err = os.ReadFile(c.KeyPath); err != nil {
		return cert, fmt.Errorf("cant open privateKey pem file: %w, path: %q", err, c.KeyPath)
	}
	if cert, err = tls.X509KeyPair(certContent, keyContent); err != nil {
		return cert, fmt.Errorf("cant load cert/key pair: %w", err)
	}
	return cert, nil
}

const (
	ClientAuthOptNone uint8 = 1 << iota >> 1
	ClientAuthOptRequest
	ClientAuthOptOptional
	ClientAuthOptVerify
)

var ClientAuthSchemes = map[uint8]tls.ClientAuthType{
	ClientAuthOptRequest:                                               tls.RequireAnyClientCert,
	ClientAuthOptRequest | ClientAuthOptVerify:                         tls.RequireAndVerifyClientCert,
	ClientAuthOptRequest | ClientAuthOptOptional:                       tls.RequestClientCert,
	ClientAuthOptRequest | ClientAuthOptOptional | ClientAuthOptVerify: tls.VerifyClientCertIfGiven,
	ClientAuthOptNone:                                                  tls.NoClientCert,
}

func DefaultTlsConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS11, MaxVersion: tls.VersionTLS13}
}

type TlsConfig struct {
	Disable        bool `json:"disable" yaml:"disable"`
	WithoutSysCA   bool `json:"without_sys_ca" yaml:"without_sys_ca"`
	SkipVerify     bool `json:"insecure_skip_verify" yaml:"insecure_skip_verify"`
	SkipVerifyHost bool `json:"skip_verify_host" yaml:"skip_verify_host"`
	ClientAuth     struct {
		Optional bool `json:"optional" yaml:"optional"`
		Request  bool `json:"request" yaml:"request"`
		Verify   bool `json:"verify" yaml:"verify"`
	} `json:"client_auth" yaml:"client_auth"`
	ServerName string            `json:"server_name" yaml:"server_name"`
	KeyLogPath string            `json:"key_log_path" yaml:"key_log_path"`
	RootCAs    []X509Cert        `json:"root_ca_list" yaml:"root_ca_list"`
	ClientCAs  []X509Cert        `json:"client_ca_list" yaml:"client_ca_list"`
	Certs      []X509CertKeyPair `json:"cert_list" yaml:"cert_list"`
}

func (tc *TlsConfig) Apply(tlsConfig *tls.Config) (err error) {
	if tlsConfig == nil {
		return nil
	}
	if tc.SkipVerifyHost || tc.SkipVerify {
		/* #nosec G402 */
		tlsConfig.InsecureSkipVerify = true
	}
	if !tc.SkipVerify && tc.SkipVerifyHost {
		tlsConfig.VerifyPeerCertificate = tlsPeerCertRootVerifier{config: tlsConfig}.VerifyPeerCertificate
	}
	if tc.ServerName != "" {
		tlsConfig.ServerName = tc.ServerName
	}
	if tc.ClientAuth.Optional || tc.ClientAuth.Request || tc.ClientAuth.Verify {
		var _clientAuthVal uint8
		if tc.ClientAuth.Request {
			_clientAuthVal |= ClientAuthOptRequest
		}
		if tc.ClientAuth.Verify {
			_clientAuthVal |= ClientAuthOptVerify
		}
		if tc.ClientAuth.Optional {
			_clientAuthVal |= ClientAuthOptOptional
		}
		if clientAuthScheme, ok := ClientAuthSchemes[_clientAuthVal]; ok {
			tlsConfig.ClientAuth = clientAuthScheme
		} else {
			return fmt.Errorf("invalid client_auth scheme: %q", _clientAuthVal)
		}
	}
	if len(tc.Certs) > 0 {
		for i := 0; i < len(tc.Certs); i++ {
			var cert tls.Certificate
			if cert, err = tc.Certs[i].BuildTLSCertificate(); err != nil {
				return fmt.Errorf("load cert[%d] failed: %w", i, err)
			}
			tlsConfig.Certificates = append(tlsConfig.Certificates, cert)
		}
	}
	if len(tc.ClientCAs) > 0 {
		tlsConfig.ClientCAs = x509.NewCertPool()
		for i := 0; i < len(tc.ClientCAs); i++ {
			var certList []*x509.Certificate
			if certList, err = tc.ClientCAs[i].BuildX509Certificate(); err != nil {
				return fmt.Errorf("load client_ca[%d] failed: %w", i, err)
			}
			for _, certItem := range certList {
				tlsConfig.ClientCAs.AddCert(certItem)
			}
		}
	}
	if tc.WithoutSysCA {
		tlsConfig.RootCAs = x509.NewCertPool()
	} else if tlsConfig.RootCAs, err = x509.SystemCertPool(); err != nil {
		return fmt.Errorf("load system root_ca pool failed: %w", err)
	}
	if len(tc.RootCAs) > 0 {
		for i := 0; i < len(tc.RootCAs); i++ {
			var certList []*x509.Certificate
			if certList, err = tc.RootCAs[i].BuildX509Certificate(); err != nil {
				return fmt.Errorf("load root_ca[%d] failed: %w", i, err)
			}
			for _, certItem := range certList {
				tlsConfig.RootCAs.AddCert(certItem)
			}
		}
	}
	if tc.KeyLogPath != "" {
		if tlsConfig.KeyLogWriter, err = os.OpenFile(tc.KeyLogPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600); err != nil {
			return fmt.Errorf("set key_log_file failed: %w", err)
		}
	}
	return nil
}

type tlsPeerCertRootVerifier struct {
	config *tls.Config
}

func (v tlsPeerCertRootVerifier) VerifyPeerCertificate(_ [][]byte, verifiedChains [][]*x509.Certificate) error {
	opts := x509.VerifyOptions{
		Roots: v.config.RootCAs,
	}
	for _, chain := range verifiedChains {
		opts.Intermediates = x509.NewCertPool()
		for i := 1; i < len(chain); i++ {
			opts.Intermediates.AddCert(chain[i])
		}
		if _, err := chain[0].Verify(opts); err != nil {
			return err
		}
	}
	return nil
}

// ============================== TLSConfig Filter / Store ==============================

type contextKey string

const ContextKeyTLSCfgFilter contextKey = "network.tls.cfg_filter"

func TLSConfigFilterContext(ctx context.Context, filter TLSConfigFilter) context.Context {
	return context.WithValue(ctx, ContextKeyTLSCfgFilter, filter)
}

type TLSConfigFilter interface {
	Apply(config *tls.Config) (*tls.Config, error)
}

type tlsNextProtoFilter []string

func NewTlsNextProtoFilter(list []string) TLSConfigFilter { return tlsNextProtoFilter(list) }

func (f tlsNextProtoFilter) Apply(config *tls.Config) (*tls.Config, error) {
	config.NextProtos = f
	return config, nil
}

type tlsConfigStore interface {
	TLSConfig() *tls.Config
}

func TLSConfigOf(source any) *tls.Config {
	if configStore, ok := source.(tlsConfigStore); ok {
		return configStore.TLSConfig()
	}
	return nil
}

// ============================== Server ==============================

type tlsServer struct {
	TlsConfig
	upstream Server
}

func (t *tlsServer) Type() string { return TypeTls }

func (t *tlsServer) Config() any { return &t.TlsConfig }

func (t *tlsServer) Addr() Addr { return t.upstream.Addr() }

func (t *tlsServer) Upstream() Server { return t.upstream }

func (t *tlsServer) ListenContext(ctx context.Context) (listener Listener, err error) {
	if t.upstream == nil {
		return nil, fmt.Errorf("%w: empty server", ErrUnsupportedUpstream)
	}
	var tc = DefaultTlsConfig()
	if err = t.TlsConfig.Apply(tc); err != nil {
		return nil, err
	}
	if filter, ok := ctx.Value(ContextKeyTLSCfgFilter).(TLSConfigFilter); ok && filter != nil {
		if tc, err = filter.Apply(tc); err != nil {
			return nil, err
		}
	}
	var upstreamListener Listener
	if upstreamListener, err = t.upstream.ListenContext(ctx); err != nil {
		return nil, err
	}
	if upstreamListener == nil {
		return nil, fmt.Errorf("%w: empty listener", ErrUnsupportedUpstream)
	}
	return &tlsListener{
		server: t, config: tc, upstream: upstreamListener, Listener: tls.NewListener(upstreamListener, tc),
	}, nil
}

func (t *tlsServer) ListenPacket(context.Context) (packetConn PacketConn, err error) {
	return nil, ErrUnsupportedProtocol
}

func NewTLSServer(config TlsConfig, upstream Server) Server {
	if config.Disable {
		return upstream
	}
	return &tlsServer{TlsConfig: config, upstream: upstream}
}

type TlsListener interface {
	tlsConfigStore
	SubListener
}

var _ TlsListener = (*tlsListener)(nil)

type tlsListener struct {
	server   *tlsServer
	config   *tls.Config
	upstream Listener
	net.Listener
}

func (tl *tlsListener) Name() string { return TypeTls }

func (tl *tlsListener) Server() Server { return tl.server }

func (tl *tlsListener) Config() *tls.Config { return tl.config }

func (tl *tlsListener) TLSConfig() *tls.Config { return tl.config }

func (tl *tlsListener) Underlying() any { return tl.Listener }

func (tl *tlsListener) Upstream() Listener { return tl.upstream }

// ============================== Client ==============================

type tlsClient struct {
	TlsConfig
	upstream Client
}

func (t *tlsClient) Type() string { return TypeTls }

func (t *tlsClient) Config() any { return &t.TlsConfig }

func (t *tlsClient) Upstream() Client { return t.upstream }

func (t *tlsClient) Dialer(ctx context.Context) (d Dialer, err error) {
	var ok bool
	if t.upstream == nil {
		return nil, fmt.Errorf("%w: empty client", ErrUnsupportedUpstream)
	}
	var tc = DefaultTlsConfig()
	if err = t.TlsConfig.Apply(tc); err != nil {
		return nil, err
	}
	var filter TLSConfigFilter
	if filter, ok = ctx.Value(ContextKeyTLSCfgFilter).(TLSConfigFilter); ok && filter != nil {
		if tc, err = filter.Apply(tc); err != nil {
			return nil, err
		}
	}
	var dialerUpStream Dialer
	if dialerUpStream, err = t.upstream.Dialer(ctx); err != nil {
		return nil, err
	}
	var netDialer *net.Dialer
	if netDialer, ok = dialerUpStream.Underlying().(*net.Dialer); !ok || netDialer == nil {
		return nil, ErrUnsupportedUpstream
	}
	return &tlsDialer{
		client:   t,
		config:   tc,
		upstream: dialerUpStream,
		Dialer: &tls.Dialer{
			NetDialer: netDialer,
			Config:    tc,
		},
	}, nil
}

func (t *tlsClient) Resolve(network, address string) (net.Addr, error) {
	return t.upstream.Resolve(strings.SplitN(network, "+", 2)[0], address)
}

func NewTLSClient(config TlsConfig, upstream Client) Client {
	if config.Disable {
		return upstream
	}
	return &tlsClient{TlsConfig: config, upstream: upstream}
}

type TlsDialer interface {
	tlsConfigStore
	SubDialer
}

var _ TlsDialer = (*tlsDialer)(nil)

type tlsDialer struct {
	*tls.Dialer
	upstream Dialer
	config   *tls.Config
	client   *tlsClient
}

func (td *tlsDialer) Config() *tls.Config { return td.config }

func (td *tlsDialer) TLSConfig() *tls.Config { return td.config }

func (td *tlsDialer) Client() Client { return td.client }

func (td *tlsDialer) Name() string { return TypeTls }

func (td *tlsDialer) Underlying() any { return td.Dialer }

func (td *tlsDialer) Upstream() Dialer { return td.upstream }
