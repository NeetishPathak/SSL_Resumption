/*SocketClient.h*/

#ifndef SOCKETCLIENT_H_
#define SOCKETCLIENT_H_

#include "common.h"

#define CLIENT_THREADS_ON FALSE

/*Keys, Certs and CA Codes*/
/*openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem*/
#define KEYS_DIR "./network/credentials/keys/"

/*RSA Keys & certificates*/
#define RSA_CLIENT_CERT_KEY_2048 KEYS_DIR "RSA/RSA_ClientKeys/client_rsa_2048.pem"
#define RSA_CLIENT_CERT_KEY_3072 KEYS_DIR "RSA/RSA_ClientKeys/client_rsa_3072.pem"

/*ECDSA keys and certificates*/
#define ECDSA_CLIENT_CERT_KEY_PRIME256V1 KEYS_DIR "EC/EC_ClientKeys/client_prime256v1_ec.pem"
#define ECDSA_CLIENT_CERT_KEY_SECP384R1 KEYS_DIR "EC/EC_ClientKeys/client_secp384r1_ec.pem"
#define ECDSA_CLIENT_CERT_KEY_SECP521R1 KEYS_DIR "EC/EC_ClientKeys/client_secp521r1_ec.pem"

/* DSA keys and certificates size 2048*/
#define DSA_CLIENT_CERT_KEY_2048 KEYS_DIR "DSA/dsa_cert_key.pem"

/*DH Paramters */
#define DHPARAMS_2048 KEYS_DIR "DHPARAMS/PARAMS/dh2048.pem"
#define DHPARAMS_1024 KEYS_DIR "DHPARAMS/PARAMS/dh1024.pem"

/*EC Parameters*/
#define ECPARAMS_PRIME256V1 KEYS_DIR "ECPARAMS/PARAMS/prime256v1.pem"
#define ECPARAMS_SECP384R1 KEYS_DIR "ECPARAMS/PARAMS/secp384r1.pem"
#define ECPARAMS_SECP521R1 KEYS_DIR "ECPARAMS/PARAMS/secp521r1.pem"

/*CA*/
#define RSA2048_SERVER_CA KEYS_DIR"RSA/RSA_ServerKeys/server_rsa_2048.pem"
#define RSA3072_SERVER_CA KEYS_DIR"RSA/RSA_ServerKeys/server_rsa_3072.pem"
#define EC_PRIME256V1_SERVER_CA KEYS_DIR"EC/EC_ServerKeys/server_prime256v1_ec.pem"
#define EC_SECP384R1_SERVER_CA KEYS_DIR"EC/EC_ServerKeys/server_primesecp384r1_ec.pem"
#define EC_SECP521R1_SERVER_CA KEYS_DIR"EC/EC_ServerKeys/server_primesecp521r1_ec.pem"
#define DSA_SERVER_CA KEYS_DIR "DSA/dsa_cert_key.pem"

/*Session File*/
#define SESS_OUT "./network/credentials/sessionFiles/sess_client.pem"


#if(CIPHERTYPE == 1 || CIPHERTYPE == 11)

#define CLIENT_CERT_KEY ECDSA_CLIENT_CERT_KEY_PRIME256V1
#define SERVER_CA	EC_PRIME256V1_SERVER_CA
#define CIPHERSUITE ECDSA256_ECDHE256
//#define EN_ECPARAMS 1
//#define EN_DHPARAMS 1

#elif(CIPHERTYPE == 2 || CIPHERTYPE == 21)

#define CLIENT_CERT_KEY RSA_CLIENT_CERT_KEY_2048
#define SERVER_CA	RSA2048_SERVER_CA
#define CIPHERSUITE RSA2048_ECDHE256
//#define EN_ECPARAMS 1
//#define EN_DHPARAMS 1

#elif(CIPHERTYPE == 3)

#define CLIENT_CERT_KEY RSA_CLIENT_CERT_KEY_2048
#define SERVER_CA	RSA2048_SERVER_CA
#define CIPHERSUITE RSA2048_DHE2048
//#define EN_ECPARAMS 0
//#define EN_DHPARAMS 1

#elif (CIPHERTYPE == 4)

#define CLIENT_CERT_KEY RSA_CLIENT_CERT_KEY_2048
#define SERVER_CA	RSA2048_SERVER_CA
#define CIPHERSUITE RSA2048_DHE1024
//#define EN_ECPARAMS 0
//#define EN_DHPARAMS 1

#elif(CIPHERTYPE == 5)

#define CLIENT_CERT_KEY RSA_CLIENT_CERT_KEY_3072
#define SERVER_CA	RSA3072_SERVER_CA
#define CIPHERSUITE RSA3072
//#define EN_ECPARAMS 0
//#define EN_DHPARAMS 0


#elif(CIPHERTYPE == 6)

#define CLIENT_CERT_KEY RSA_CLIENT_CERT_KEY_2048
#define SERVER_CA	RSA2048_SERVER_CA
#define CIPHERSUITE RSA2048
//#define EN_ECPARAMS 0
//#define EN_DHPARAMS 0

#elif(CIPHERTYPE == 7 || CIPHERTYPE == 71)

#define CLIENT_CERT_KEY ECDSA_CLIENT_CERT_KEY_PRIME256V1
#define SERVER_CA	EC_PRIME256V1_SERVER_CA
#define CIPHERSUITE TLS1_3_AES128
//#define EN_ECPARAMS 0
//#define EN_DHPARAMS 0

#elif(CIPHERTYPE == 8 || CIPHERTYPE == 81)

#define CLIENT_CERT_KEY RSA_CLIENT_CERT_KEY_2048
#define SERVER_CA	RSA2048_SERVER_CA
#define CIPHERSUITE TLS1_3_AES128
//#define EN_ECPARAMS 0
//#define EN_DHPARAMS 0

#else

#define CLIENT_CERT_KEY RSA_CLIENT_CERT_KEY_2048
#define SERVER_CA	RSA2048_SERVER_CA
#define DHPARAMS DHPARAMS_2048
#define ECPARAMS ECPARAMS_PRIME256V1
#define CIPHERSUITE RSA2048_ECDHE256
//#define EN_ECPARAMS 1
//#define EN_DHPARAMS 1

#endif


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
	std::ofstream clientOpFile;
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
