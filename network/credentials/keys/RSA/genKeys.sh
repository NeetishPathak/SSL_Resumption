
#enter the RSA key size (1024, 2048, 4096 etc)
#Generate RSA 2048b keys and certs 
openssl req -newkey rsa:2048 -nodes -config config.cnf  -keyout client_rsa_key.pem -x509 -days 730 -out client_rsa_cert.pem
cat client_rsa_key.pem client_rsa_cert.pem > ./RSA_ClientKeys/client_rsa_2048.pem
openssl req -newkey rsa:2048 -nodes -config config.cnf  -keyout server_rsa_key.pem -x509 -days 730 -out server_rsa_cert.pem
cat server_rsa_key.pem server_rsa_cert.pem > ./RSA_ServerKeys/server_rsa_2048.pem
rm client_rsa_key.pem client_rsa_cert.pem server_rsa_key.pem server_rsa_cert.pem

#Generate RSA 3072 keys and certs
openssl req -newkey rsa:3072 -nodes -config config.cnf  -keyout client_rsa_key.pem -x509 -days 730 -out client_rsa_cert.pem
cat client_rsa_key.pem client_rsa_cert.pem > ./RSA_ClientKeys/client_rsa_3072.pem
openssl req -newkey rsa:3072 -nodes -config config.cnf  -keyout server_rsa_key.pem -x509 -days 730 -out server_rsa_cert.pem
cat server_rsa_key.pem server_rsa_cert.pem > ./RSA_ServerKeys/server_rsa_3072.pem
rm client_rsa_key.pem client_rsa_cert.pem server_rsa_key.pem server_rsa_cert.pem
