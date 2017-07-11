/********************************************************************
 * Filename : SocketServer.h
 * Author: Neetish Pathak (nepathak@paypal.com)
 * Description: 1) contains class definition for SocketServer class.
 *				2) macros related to server certificates and keys
 ********************************************************************/
/*SocketServer.h*/

#ifndef SOCKETSERVER_H_
#define SOCKETSERVER_H_

#include "common.h"
#include <signal.h>
#include <atomic>

/*Keys and Certificates*/
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

/*ciphers for TLS 1.3*/
#define TLS13_AES_128_GCM_SHA256_BYTES  ((const unsigned char *)"\x13\x01")
#define TLS13_AES_256_GCM_SHA384_BYTES  ((const unsigned char *)"\x13\x02")

/*simple_ssl_session_st struct for session caching on server side*/
typedef struct simple_ssl_session_st {
    unsigned char *id;
    unsigned int idlen;
    unsigned char *der;
    int derlen;
    struct simple_ssl_session_st *next;
} simple_ssl_session;

class SocketServer{
private:
	std::string portNumber;
	bool clientConnected;
	SSL_CTX *ssl_ctx;
	SSL* conn;
	BIO	*bio, *bioClient;
	std::string serverCertKey;
	std::string clientCA;
	std::string dhParams;
	std::string ecParams;
	bool enableDhParams;
	bool enableEcParams;
	void loadServerKeys(cipher_t);
public:
	SocketServer(std::string portNumber, test_Case_Num tc, cipher_t c);
	virtual int listen();
	virtual int send(std::string message);
	virtual std::string receive(int size);
	virtual ~SocketServer();
};

#endif
