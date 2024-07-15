```go
package main

import (
	"crypto/tls"
	"fmt"
	"github.com/tlsproxy/pgproxy"
)

func main() {
	proxyConfig := &pgproxy.ProxyConfig{
		Src: "0.0.0.0:7777",
		Dst: "192.168.1.11:5432",
		HandleError: func(err error) {
			fmt.Printf("%+v", err)
		},
		HandleRead: func(b []byte, state tls.ConnectionState) error {
			return nil
		},
		HandleWrite: nil,
		HandleClientState: func(w tls.ConnectionState) error {
			return nil
		},
	}

	tlsConfig := &pgproxy.TlsConfig{
		ServerCert: "/Users/zeuszhao/Workspace/godev/study/ca/server.crt",
		ServerKey:  "/Users/zeuszhao/Workspace/godev/study/ca/server.key",
		CaCert:     "/Users/zeuszhao/Workspace/godev/study/ca/ca.crt",
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