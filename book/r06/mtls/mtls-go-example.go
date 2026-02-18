package main

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
	"os"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			log.Printf("Client certificate CN: %s", r.TLS.PeerCertificates[0].Subject.CommonName)
		}
		w.Write([]byte("Secure mTLS connection established"))
	})

	server := createMTLSServer()
	log.Fatal(server.ListenAndServeTLS("server.pem", "server.key"))
}

func createMTLSServer() *http.Server {
	caCert, err := os.ReadFile("ca/cacert.pem")
	if err != nil {
		log.Fatalf("Failed to read CA cert: %v", err)
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caCert) {
		log.Fatal("Failed to parse CA certificate")
	}

	return &http.Server{
		Addr: ":8443",
		TLSConfig: &tls.Config{
      // Ta linia włącza mTLS, wymagając od klienta przedstawienia
      // i zweryfikowania swojego certyfikatu.
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    certPool,
			MinVersion:   tls.VersionTLS13,
			CipherSuites: []uint16{
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
			},
		},
	}
}
