HOMEDIR="/home/jurek/.gnupg/"
FILENAME="/tmp/test.txt"
ENCRYPTED="/tmp/test.asc"
RECIPIENT="jurek@example.com"

echo "Testowy plik" > $FILENAME

rm $ENCRYPTED

gpg2  --armor -vv \
     --homedir $HOMEDIR \
     --recipient $RECIPIENT \
     --output $ENCRYPTED \
     --encrypt $FILENAME 


ls -l $ENCRYPTED

echo "OK - teraz rozszyfrowanie"


gpg2         --armor  --no-version \
            --always-trust \
            --homedir $HOMEDIR \
            --decrypt $ENCRYPTED
