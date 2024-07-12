package pgproxy

import (
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5/pgproto3"
	"io"
	"net"
)

var (
	ErrorNotSSLRequest = errors.New("client request not ssl")
)

type ProxyConfig struct {
	Src string
	Dst string

	HandleError func(err error)
	HandleRead  func(b []byte, w tls.ConnectionState) error
	HandleWrite func(b []byte, w tls.ConnectionState) error
}

type Proxy struct {
	ProxyConfig *ProxyConfig
	TlsConfig   *TlsConfig
}

func NewProxy(config *ProxyConfig, tlsConfig *TlsConfig) (*Proxy, error) {
	if config.HandleError == nil {
		config.HandleError = func(err error) {}
	}

	if config.HandleWrite == nil {
		config.HandleWrite = func(b []byte, w tls.ConnectionState) error { return nil }
	}

	if config.HandleRead == nil {
		config.HandleRead = func(b []byte, w tls.ConnectionState) error { return nil }
	}

	return &Proxy{
		ProxyConfig: config,
		TlsConfig:   tlsConfig,
	}, nil
}

func (p *Proxy) Listen() error {
	srcListener, err := net.Listen("tcp", p.ProxyConfig.Src)
	if err != nil {
		return err
	}

	for {
		srcConn, err := srcListener.Accept()
		if err != nil {
			p.ProxyConfig.HandleError(err)
			continue
		}

		go func() {
			defer func() {
				if r := recover(); r != nil {
					err = fmt.Errorf("conn error %v", r)
					p.ProxyConfig.HandleError(err)
				}
			}()
			p.handleConn(srcConn)
		}()
	}
}

func (p *Proxy) handleConn(srcConn net.Conn) {
	err := p.forward(srcConn)
	if err != nil {
		p.ProxyConfig.HandleError(err)
	}
}

func (p *Proxy) forward(srcConn net.Conn) error {
	backend := pgproto3.NewBackend(srcConn, nil)
	startupMessage, err := backend.ReceiveStartupMessage()
	if err != nil {
		return err
	}

	tlsSrcConn := &tls.Conn{}
	switch startupMessage.(type) {
	case *pgproto3.SSLRequest:
		_, err = srcConn.Write([]byte{'S'})
		if err != nil {
			return err
		}
		tlsSrcConn, err = p.handshake(srcConn)
	default:
		_, err = srcConn.Write([]byte{'N'})
		if err != nil {
			return err
		}
		return ErrorNotSSLRequest
	}

	dstConn, err := net.Dial("tcp", p.ProxyConfig.Dst)
	if err != nil {
		return err
	}

	state := tlsSrcConn.ConnectionState()
	tlsConn1 := &connReadWriteCloser{srcConn: tlsSrcConn, r: p.ProxyConfig.HandleRead, w: p.ProxyConfig.HandleWrite, srcState: state}
	pgConn1 := &connReadWriteCloser{srcConn: dstConn, r: p.ProxyConfig.HandleRead, w: p.ProxyConfig.HandleWrite, srcState: state}

	c := make(chan error)
	go func() {
		_, err = io.Copy(tlsConn1, pgConn1)
		c <- err
	}()
	go func() {
		_, err = io.Copy(pgConn1, tlsConn1)
		c <- err
	}()

	err = <-c
	if err != nil {
		_ = tlsSrcConn.Close()
		_ = dstConn.Close()
	}
	return err
}

func (p *Proxy) handshake(srcConn net.Conn) (*tls.Conn, error) {
	tlsConfig, err := NewTlsConfig(p.TlsConfig)
	if err != nil {
		return nil, err
	}
	tlsSrcConn := tls.Server(srcConn, tlsConfig)
	err = tlsSrcConn.Handshake()
	if err != nil {
		return nil, err
	}
	return tlsSrcConn, nil
}

type connReadWriteCloser struct {
	srcConn  net.Conn
	srcState tls.ConnectionState
	r        func(b []byte, w tls.ConnectionState) error
	w        func(b []byte, w tls.ConnectionState) error
}

func (c *connReadWriteCloser) Read(p []byte) (int, error) {
	n, err := c.srcConn.Read(p)
	if err != nil {
		return 0, err
	}
	err = c.r(p, c.srcState)
	if err != nil {
		return 0, err
	}
	return n, nil
}

func (c *connReadWriteCloser) Write(p []byte) (int, error) {
	n, err := c.srcConn.Write(p)
	if err != nil {
		return 0, err
	}
	err = c.w(p, c.srcState)
	if err != nil {
		return 0, err
	}
	return n, nil
}
