```go
func main() {
	proxyConfig := &pgproxy.ProxyConfig{
		Src: "0.0.0.0:7777",
		Dst: "192.168.1.1:5432",
		HandleError: func(err error) {
			fmt.Printf("%+v", err)
		},
		HandleRead: func(b []byte, w tls.ConnectionState) error {
			fmt.Println(w.PeerCertificates[0].Issuer)
			return nil
		},
		HandleWrite: nil,
	}

	tlsConfig := &pgproxy.TlsConfig{
		ServerCert: "/ca/server.crt",
		ServerKey:  "/ca/server.key",
		CaCert:     "/ca/ca.crt",
	}

	proxy, err := pgproxy.NewProxy(proxyConfig, tlsConfig)
	if err != nil {
		panic(err)
	}

	err = proxy.Listen()
	if err != nil {
		panic(err)
	}
}

```