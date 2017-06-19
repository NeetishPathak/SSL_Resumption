/*SocketClient.h*/

#ifndef SOCKETCLIENT_H_
#define SOCKETCLIENT_H_

#include "common.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string>
#include <time.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <iostream>
#include <thread>

#define CLIENT_THREADS_ON FALSE

/*openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem*/

#define CLIENT_CERT	(CIPHERTYPE==RSA_KEY)?"./network/credentials/keys/RSA/client_rsa.pem":"./network/credentials/keys/EC/client_ec.pem"
#define CLIENT_KEY	(CIPHERTYPE==RSA_KEY)?"./network/credentials/keys/RSA/client_rsa.pem":"./network/credentials/keys/EC/client_ec.pem"
#define DHPARAMS "./network/credentials/keys/DHPARAMS/dh2048.pem"
#define SESS_OUT "./network/credentials/sessionFiles/sess_client.pem"

class SocketClient{
private:
	std::string serverName;
	std::string portNumber;
	bool isConnected;
	SSL_CTX *ssl_ctx;
	SSL* conn;
	BIO* bio;
	SSL_SESSION *sessionId;
	int handshakes;

public:
	typedef int (SocketClient::*cb_ptr)(SSL * , SSL_SESSION *);
	cb_ptr new_sess;
	SocketClient(std::string serverName, std::string portNumber);
	virtual int connectToServer();
	virtual std::pair<uint64_t, double> sslTcpConnect();
	virtual int sslTcpClosure();
	virtual int disconnectFromServer();
	virtual int send(std::string message);
	virtual std::string receive(int size);
	//virtual int sessGetCb();
	bool isServerConnected(){return this->isConnected;}
	virtual ~SocketClient();
};

#endif
