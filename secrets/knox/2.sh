# wykonaj jako root / sudo
export PATH=$PATH:/usr/local/go/bin
export GOPATH=/usr/local/go
export GO17VENDOREXPERIMENT=1
go install github.com/pinterest/knox/cmd/dev_client@latest