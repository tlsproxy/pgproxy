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
		Dst: "192.168.1.11:32432",
		HandleError: func(err error) {
			fmt.Printf("%+v", err)
		},
		HandleRead: func(b []byte) error {
			return nil
		},
		HandleWrite: nil,
		HandleClientState: func(w tls.ConnectionState) error {
			return nil
		},
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