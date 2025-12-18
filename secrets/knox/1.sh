# wykonaj jako root / sudo
export PATH=$PATH:/usr/local/go/bin
export GOPATH=/usr/local/go
export GO17VENDOREXPERIMENT=1
go get -d github.com/pinterest/knox
go install github.com/pinterest/knox/cmd/dev_server@latest

