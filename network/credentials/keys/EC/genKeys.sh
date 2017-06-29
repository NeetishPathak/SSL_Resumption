openssl ecparam -name prime256v1 -genkey -param_enc named_curve -out server_key.pem
openssl req -new -config config.cnf -x509 -key server_key.pem -out server_cert.pem -days 730
cat server_key.pem server_cert.pem > ./EC_ServerKeys/server_prime256v1_ec.pem
rm server_key.pem server_cert.pem
openssl ecparam -name prime256v1 -genkey -param_enc named_curve -out client_key.pem
openssl req -new -config config.cnf -x509 -key client_key.pem -out client_cert.pem -days 730
cat client_key.pem client_cert.pem > ./EC_ClientKeys/client_prime256v1_ec.pem
rm client_key.pem client_cert.pem

openssl ecparam -name secp521r1 -genkey -param_enc named_curve -out server_key.pem
openssl req -new -config config.cnf -x509 -key server_key.pem -out server_cert.pem -days 730
cat server_key.pem server_cert.pem > ./EC_ServerKeys/server_secp521r1_ec.pem
rm server_key.pem server_cert.pem
openssl ecparam -name secp521r1 -genkey -param_enc named_curve -out client_key.pem
openssl req -new -config config.cnf -x509 -key client_key.pem -out client_cert.pem -days 730
cat client_key.pem client_cert.pem > ./EC_ClientKeys/client_secp521r1_ec.pem
rm client_key.pem client_cert.pem

openssl ecparam -name secp384r1 -genkey -param_enc named_curve -out server_key.pem
openssl req -new -config config.cnf -x509 -key server_key.pem -out server_cert.pem -days 730
cat server_key.pem server_cert.pem > ./EC_ServerKeys/server_secp384r1_ec.pem
rm server_key.pem server_cert.pem
openssl ecparam -name secp384r1 -genkey -param_enc named_curve -out client_key.pem
openssl req -new -config config.cnf -x509 -key client_key.pem -out client_cert.pem -days 730
cat client_key.pem client_cert.pem > ./EC_ClientKeys/client_secp384r1_ec.pem
rm client_key.pem client_cert.pem
