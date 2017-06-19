openssl ecparam -name $1 -genkey -param_enc explicit -out server_key.pem
openssl req -new -x509 -key server_key.pem -out server_cert.pem -days 730
cat server_key.epm server_cert.pem > server_ec.pem
openssl ecparam -name $1 -genkey -param_enc explicit -out client_key.pem
openssl req -new -x509 -key client_key.pem -out client_cert.pem -days 730
cat client_key.pem client_cert.pem > client_ec.pem
