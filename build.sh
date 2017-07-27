g++ -g -O0 -w -DEARLY=$1 -std=c++11 -pthread client.cpp ./network/SocketClient.cpp ./network/common.cpp -o client ./../openssl/libssl.a ./../openssl/libcrypto.a -ldl
g++ -g -O0 -w -DEARLY=$1 -std=c++11 -pthread server.cpp ./network/SocketServer.cpp ./network/common.cpp -o server ./../openssl/libssl.a ./../openssl/libcrypto.a -ldl
