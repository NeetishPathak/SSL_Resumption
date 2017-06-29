#Generate passphrase protected DSA keys (keep an easy password for testing purpose e.g. test use : openssl dsaparam -genkey 2048 | openssl dsa -out dsa.pem)
openssl dsaparam -genkey 2048 | openssl dsa -out dsa.pem
#Generate a self signed certificate
openssl req -new -config config.cnf -x509 -days 365 -key dsa.pem -out dsa_cert.pem
cat dsa.pem dsa_cert.pem > dsa_cert_key.pem
rm dsa.pem dsa_cert.pem
