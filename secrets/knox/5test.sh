TOKEN=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

export GOPATH=/usr/local/go
export KNOX_USER_AUTH=$TOKEN

echo "odczyt sekretu"
$GOPATH/bin/dev_client get test_service:first_secret

echo ""
echo "W postaci json:"
$GOPATH/bin/dev_client get -j test_service:first_secret

echo ""
echo "Listuj:"
$GOPATH/bin/dev_client keys
