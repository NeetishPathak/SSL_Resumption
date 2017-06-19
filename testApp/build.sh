gcc -g -lpthread client.c ./common.c -o client ./../../openssl/libssl.a ./../../openssl/libcrypto.a
gcc -g -lpthread server.c ./common.c -o server ./../../openssl/libssl.a ./../../openssl/libcrypto.a
