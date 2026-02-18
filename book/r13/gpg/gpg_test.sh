FILENAME="/tmp/test.txt"
ENCRYPTED="/tmp/test.asc"
RECIPIENT="jurek@example.com"
PASSPHRASE="haslo"

echo "Testowy plik" > $FILENAME
gpg --armor --recipient $RECIPIENT --output $ENCRYPTED --encrypt $FILENAME
gpg --armor --passphrase $PASSPHRASE --decrypt $ENCRYPTED
