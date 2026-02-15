# Create a private key:
certtool -p --outfile cert.key.pem
# Generate the self-signed certificate:
certtool -s --load-privkey cert.key.pem --outfile cert.crt.pem
