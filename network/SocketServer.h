/*SocketServer.h*/

#ifndef SOCKETSERVER_H_
#define SOCKETSERVER_H_

#include "common.h"
#include <string>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <iostream>
#include <string>
//#include <thread>
#include <assert.h>



/*openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem*/
#define SERVER_CERT (CIPHERTYPE==RSA_KEY)?"./network/credentials/keys/RSA/server_rsa.pem":"./network/credentials/keys/EC/server_ec.pem"
#define SERVER_KEY  (CIPHERTYPE==RSA_KEY)?"./network/credentials/keys/RSA/server_rsa.pem":"./network/credentials/keys/EC/server_ec.pem"
#define DHPARAMS "./network/credentials/keys/DHPARAMS/dh2048.pem"
#define ECPARAMS "./network/credentials/keys/EC/server_ec.pem"

class SocketServer{
private:
	std::string portNumber;
	bool clientConnected;
	SSL_CTX *ssl_ctx;
	SSL* conn;
	BIO	*bio, *bioClient;
	
public:
	SocketServer(std::string portNumber);
	virtual int listen();
	virtual int send(std::string message);
	virtual std::string receive(int size);
	virtual ~SocketServer();
};

#endif
