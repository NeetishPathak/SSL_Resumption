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
#include <signal.h>
#include <unistd.h>
#include <atomic>



/*openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem*/
#define KEYS_DIR "./network/credentials/keys/"

/*RSA Keys & certificates*/
#define RSA_SERVER_CERT_KEY_2048 KEYS_DIR "RSA/RSA_ServerKeys/server_rsa_2048.pem"
#define RSA_SERVER_CERT_KEY_3072 KEYS_DIR "RSA/RSA_ServerKeys/server_rsa_3072.pem"

/*ECDSA keys and certificates*/
#define ECDSA_SERVER_CERT_KEY_PRIME256V1 KEYS_DIR "EC/EC_ServerKeys/server_prime256v1_ec.pem"
#define ECDSA_SERVER_CERT_KEY_SECP384R1 KEYS_DIR "EC/EC_ServerKeys/server_secp384r1_ec.pem"
#define ECDSA_SERVER_CERT_KEY_SECP521R1 KEYS_DIR "EC/EC_ServerKeys/server_secp521r1_ec.pem"

/* DSA keys and certificates size 2048*/
#define DSA_SERVER_CERT_KEY_2048 KEYS_DIR "DSA/dsa_cert_key.pem"

/*DH Paramters */
#define DHPARAMS_2048 KEYS_DIR "DHPARAMS/PARAMS/dh2048.pem"
#define DHPARAMS_1024 KEYS_DIR "DHPARAMS/PARAMS/dh1024.pem"

/*EC Parameters*/
#define ECPARAMS_PRIME256V1 KEYS_DIR "ECPARAMS/PARAMS/prime256v1.pem"
#define ECPARAMS_SECP384R1 KEYS_DIR "ECPARAMS/PARAMS/secp384r1.pem"
#define ECPARAMS_SECP521R1 KEYS_DIR "ECPARAMS/PARAMS/secp521r1.pem"

/*CA*/
#define RSA2048_CLIENT_CA KEYS_DIR"RSA/RSA_ClientKeys/client_rsa_2048.pem"
#define RSA3072_CLIENT_CA KEYS_DIR"RSA/RSA_ClientKeys/client_rsa_3072.pem"
#define EC_PRIME256V1_CLIENT_CA KEYS_DIR"EC/EC_ClientKeys/client_prime256v1_ec.pem"
#define EC_SECP384R1_CLIENT_CA KEYS_DIR"EC/EC_ClientKeys/client_secp384r1_ec.pem"
#define EC_SECP521R1_CLIENT_CA KEYS_DIR"EC/EC_ClientKeys/client_secp521r1_ec.pem"
#define DSA_CLIENT_CA KEYS_DIR "DSA/dsa_cert_key.pem"


#if(CIPHERTYPE == 1)

#define SERVER_CERT_KEY ECDSA_SERVER_CERT_KEY_PRIME256V1
#define CLIENT_CA	EC_PRIME256V1_CLIENT_CA
#define DHPARAMS DHPARAMS_2048
#define ECPARAMS ECPARAMS_PRIME256V1
#define EN_ECPARAMS 0
#define EN_DHPARAMS 0

#elif(CIPHERTYPE == 11)

#define SERVER_CERT_KEY ECDSA_SERVER_CERT_KEY_PRIME256V1
#define CLIENT_CA	EC_PRIME256V1_CLIENT_CA
#define DHPARAMS DHPARAMS_2048
#define ECPARAMS ECPARAMS_PRIME256V1
#define EN_ECPARAMS 1
#define EN_DHPARAMS 1

#elif(CIPHERTYPE == 2)

#define SERVER_CERT_KEY RSA_SERVER_CERT_KEY_2048
#define CLIENT_CA	RSA2048_CLIENT_CA
#define DHPARAMS DHPARAMS_2048
#define ECPARAMS ECPARAMS_PRIME256V1
#define EN_ECPARAMS 0
#define EN_DHPARAMS 0

#elif(CIPHERTYPE == 21)

#define SERVER_CERT_KEY RSA_SERVER_CERT_KEY_2048
#define CLIENT_CA	RSA2048_CLIENT_CA
#define DHPARAMS DHPARAMS_2048
#define ECPARAMS ECPARAMS_PRIME256V1
#define EN_ECPARAMS 1
#define EN_DHPARAMS 1

#elif(CIPHERTYPE == 3)

#define SERVER_CERT_KEY RSA_SERVER_CERT_KEY_2048
#define CLIENT_CA	RSA2048_CLIENT_CA
#define DHPARAMS DHPARAMS_2048
#define ECPARAMS ECPARAMS_PRIME256V1
#define EN_ECPARAMS 0
#define EN_DHPARAMS 1

#elif (CIPHERTYPE == 4)

#define SERVER_CERT_KEY RSA_SERVER_CERT_KEY_2048
#define CLIENT_CA	RSA2048_CLIENT_CA
#define DHPARAMS DHPARAMS_1024
#define ECPARAMS ECPARAMS_PRIME256V1
#define EN_ECPARAMS 0
#define EN_DHPARAMS 1

#elif(CIPHERTYPE == 5)

#define SERVER_CERT_KEY RSA_SERVER_CERT_KEY_3072
#define CLIENT_CA	RSA3072_CLIENT_CA
#define DHPARAMS DHPARAMS_2048
#define ECPARAMS ECPARAMS_PRIME256V1
#define EN_ECPARAMS 0
#define EN_DHPARAMS 0


#elif(CIPHERTYPE == 6)

#define SERVER_CERT_KEY RSA_SERVER_CERT_KEY_2048
#define CLIENT_CA	RSA2048_CLIENT_CA
#define DHPARAMS DHPARAMS_2048
#define ECPARAMS ECPARAMS_PRIME256V1
#define EN_ECPARAMS 0
#define EN_DHPARAMS 0


#elif(CIPHERTYPE == 7)

#define SERVER_CERT_KEY ECDSA_SERVER_CERT_KEY_PRIME256V1
#define CLIENT_CA	EC_PRIME256V1_CLIENT_CA
#define DHPARAMS DHPARAMS_2048
#define ECPARAMS ECPARAMS_PRIME256V1
#define EN_ECPARAMS 1
#define EN_DHPARAMS 1

#elif(CIPHERTYPE == 8)

#define SERVER_CERT_KEY RSA_SERVER_CERT_KEY_2048
#define CLIENT_CA	RSA2048_CLIENT_CA
#define DHPARAMS DHPARAMS_2048
#define ECPARAMS ECPARAMS_PRIME256V1
#define EN_ECPARAMS 0
#define EN_DHPARAMS 0
#else

#endif

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
