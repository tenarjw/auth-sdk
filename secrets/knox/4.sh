TOKEN=<wygenerowany token>

export GOPATH=/usr/local/go
export KNOX_USER_AUTH=$TOKEN
echo -n "My first knox secret" | $GOPATH/bin/dev_client create test_service:first_secret
