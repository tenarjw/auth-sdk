Uwaga! 

1) Moduł signing korzysta z programu xmlsec1 - musi on być dostępny w systemie!

2) Certyfikat musi być kwalifikowany - nawet do testów. Self-sined tylko do testowania bez transmisji.


Biblioteka xmlsec może wymagać instalacji dodatkowych pakietów systemowych.
W systemach Debian/Ubuntu: 
```
sudo apt-get install build-essential libxml2-dev libxslt1-dev xmlsec1-dev
```

W systemach RedHat/Fedora: 
```
sudo dnf install gcc libxml2-devel libxslt-devel xmlsec1-devel xmlsec1-openssl-devel
```

Na macOS (z Homebrew): 
```
brew install libxml2 libxslt xmlsec1
```