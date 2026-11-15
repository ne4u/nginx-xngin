// TLS transport for engine<->agent connections.
//
// The engine connects as the TLS client; the agent is the TLS server.
// For FedRAMP/FIPS builds use `GOEXPERIMENT=boringcrypto` or Go >= 1.24
// with `GOFIPS140=v1.0.0` — crypto/tls then runs on the FIPS-validated
// module with no code changes.
package xngin

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
)

// TLSConfig builds the agent-side *tls.Config from PEM files.
// clientCAFile enables mutual TLS: the engine must present a client
// certificate signed by that CA. Omit it for server-auth-only TLS.
func TLSConfig(certFile, keyFile, clientCAFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	if clientCAFile != "" {
		pem, err := os.ReadFile(clientCAFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("xngin: no certs in client CA file")
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return cfg, nil
}
