package main

import (
  "crypto/tls"
  "crypto/x509"
  "fmt"
  "io/ioutil"
  "log"
  "net/http"
)

var domain = "localhost"

func main() {

  http.HandleFunc("/", func(rw http.ResponseWriter, r *http.Request) {
    rw.Header().Set("Content-Type", "text/plain")
    fmt.Fprint(rw, "Hello World")
  })

  server := &http.Server{Addr: ":8443"}
  server = createServerWithMTLS()

  // Start the server loading the certificate and key
  err := server.ListenAndServeTLS("server.pem", "server.key")
  if err != nil {
    log.Fatal("Unable to start server", err)
  }
}

func createServerWithMTLS() *http.Server {
  // Add the cert chain as the intermediate signs both the servers and the clients certificates
  clientCACert, err := ioutil.ReadFile("ca/cacert.pem")
  if err != nil {
    log.Fatal(err)
  }

  clientCertPool := x509.NewCertPool()
  clientCertPool.AppendCertsFromPEM(clientCACert)

  tlsConfig := &tls.Config{
    ClientAuth:               tls.RequireAndVerifyClientCert,
    ClientCAs:                clientCertPool,
    PreferServerCipherSuites: true,
    MinVersion:               tls.VersionTLS12,
  }

  tlsConfig.BuildNameToCertificate()

  return &http.Server{
    Addr:      ":8443",
    TLSConfig: tlsConfig,
  }
}
