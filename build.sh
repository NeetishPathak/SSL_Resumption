g++ -g -w -DTESTCASE=$1 -DCIPHERTYPE=$2 -std=c++11 -pthread client.cpp ./network/SocketClient.cpp ./network/common.cpp -o client ./../openssl/libssl.a ./../openssl/libcrypto.a -ldl
g++ -g -w -DTESTCASE=$1 -DCIPHERTYPE=$2 -std=c++11 -pthread server.cpp ./network/SocketServer.cpp ./network/common.cpp -o server ./../openssl/libssl.a ./../openssl/libcrypto.a -ldl
