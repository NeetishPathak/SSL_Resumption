
#enter the size (1024, 2048, 4096 etc)
openssl req -newkey rsa:$1 -nodes -keyout client_rsa_key.pem -x509 -days 730 -out client_rsa_cert.pem
cat client_rsa_key.pem client_rsa_cert.pem > client_rsa.pem
openssl req -newkey rsa:$1 -nodes -keyout server_rsa_key.pem -x509 -days 730 -out server_rsa_cert.pem
cat server_rsa_key.pem server_rsa_cert.pem > server_rsa.pem

