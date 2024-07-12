package pgproxy

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
)

type TlsConfig struct {
	ServerCert string
	ServerKey  string
	CaCert     string
}

func NewTlsConfig(config *TlsConfig) (*tls.Config, error) {
	serverCert, err := tls.LoadX509KeyPair(config.ServerCert, config.ServerKey)
	if err != nil {
		return &tls.Config{}, err
	}

	cas := x509.NewCertPool()
	serverCA, err := ioutil.ReadFile(config.CaCert)
	if err != nil {
		return &tls.Config{}, err
	}
	if ok := cas.AppendCertsFromPEM(serverCA); !ok {
		return &tls.Config{}, err
	}

	tlsConfig := tls.Config{Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: cas}
	tlsConfig.Rand = rand.Reader
	return &tlsConfig, nil
}
