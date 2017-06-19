g++ -g -std=c++11 -lpthread client.cpp ./network/SocketClient.cpp ./network/common.cpp -o client ./../openssl/libssl.a ./../openssl/libcrypto.a
g++ -g -std=c++11 -lpthread server.cpp ./network/SocketServer.cpp ./network/common.cpp -o server ./../openssl/libssl.a ./../openssl/libcrypto.a
