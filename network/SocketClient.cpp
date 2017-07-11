/********************************************************************
 * Filename : SocketClient.cpp
 * Author: Neetish Pathak (nepathak@paypal.com)
 * Description: 1) contains class implementation of SocketClient class.
 *				2) Callback functions for session info update and use
 ********************************************************************/

#include "SocketClient.h"
using namespace std;

/*Session Related data*/
SSL_SESSION *sessionDet = NULL;
char *sess_out = NULL;
bool resumeInput = TRUE;
static SSL_SESSION *psksess = NULL;
BIO * bio_err = BIO_new_fp(stderr,0x00 | (((1 | 0x8000) & 0x8000) == 0x8000 ? 0x10 : 0));

/* Default PSK identity and key */
static char *psk_identity = "Client_identity";

/***********************************************************************
 * Function: psk_use_session_cb
 * Parameters: SSL *s, const EVP_MD *md, const unsigned char **id,
 * 			   size_t *idlen, SSL_SESSION **sess
 * Return type: int
 * Description: callback function for the session re-use using ext PSK
 * 				with TLS 1.3 (referenced from s_client.c in openssl code)
 * *********************************************************************/
static int psk_use_session_cb(SSL *s, const EVP_MD *md,
                              const unsigned char **id, size_t *idlen,
                              SSL_SESSION **sess)
{
    SSL_SESSION *usesess = NULL;
    const SSL_CIPHER *cipher = NULL;

    if (psksess != NULL) { //check if the session is read from a file
    	cout << "Session found on client side File" << endl;
        SSL_SESSION_up_ref(psksess);
        usesess = psksess;
    } else { //Session not found in a file, create a new session

        long key_len;
        unsigned char *key = OPENSSL_hexstr2buf(psk_key, &key_len);

        if (key == NULL) {
            BIO_printf(bio_err, "Could not convert PSK key '%s' to buffer\n",
                       psk_key);
            return 0;
        }

        if (key_len == EVP_MD_size(EVP_sha256()))
            cipher = SSL_CIPHER_find(s, tls13_aes128gcmsha256_id);
        else if(key_len == EVP_MD_size(EVP_sha384()))
            cipher = SSL_CIPHER_find(s, tls13_aes256gcmsha384_id);

        if (cipher == NULL) {
            /* Doesn't look like a suitable TLSv1.3 key. Ignore it */
            OPENSSL_free(key);
            *id = NULL;
            *idlen = 0;
            *sess = NULL;
            return 0;
        }
        usesess = SSL_SESSION_new();
        if (usesess == NULL
                || !SSL_SESSION_set1_master_key(usesess, key, key_len)
                || !SSL_SESSION_set_cipher(usesess, cipher)
                || !SSL_SESSION_set_protocol_version(usesess, TLS1_3_VERSION)) {
            OPENSSL_free(key);
            goto err;
        }
        OPENSSL_free(key);
    }

    cipher = SSL_SESSION_get0_cipher(usesess);
    if (cipher == NULL)
        goto err;
    if (md != NULL && SSL_CIPHER_get_handshake_digest(cipher) != md) {
        /* PSK not usable, ignore it */
        *id = NULL;
        *idlen = 0;
        *sess = NULL;
        SSL_SESSION_free(usesess);
    } else {
        *sess = usesess;
        *id = (unsigned char *)psk_identity;
        *idlen = strlen(psk_identity);
    }
    return 1;

 err:
    SSL_SESSION_free(usesess);
    return 0;
}

/***********************************************************************
 * Function: new_session_cb
 * Parameters: SSL* ssl, SSL_SESSION * sess
 * Return type: int
 * Description: callback function for the new session callback
 * 				save the session info in the session file
 * 				(referenced from s_client.c in openssl code)
 * *********************************************************************/
static int new_session_cb(SSL* ssl, SSL_SESSION * sess){


	BIO *stmp = BIO_new_file(sess_file,"w");

	if(stmp == NULL){
		BIO_printf(bio_err,"Error writing session file %s\n",sess_file);
	}else{
		PEM_write_bio_SSL_SESSION(stmp,sess);
		BIO_free(stmp);
		resumeInput = TRUE;
		if(FALSE){
			fprintf(stderr,"SocketClient.cpp: Session is saved on client Side");
			SSL_SESSION_print_keylog(bio_err, sess);
			BIO_printf(bio_err,"");
		}
	}

	return 0;

}

/***********************************************************************
 * Function: SocketClient
 * Parameters: string serverName, string portNumber,
 * 			   test_Case_Num tcNo, cipher_t cipherType
 * Return type: NA (constructor)
 * Description: SocketClient constructor
 * 				Initialize the client side attributes
 * *********************************************************************/
SocketClient::SocketClient(string serverName, string portNumber, test_Case_Num tcNo, cipher_t cipherType){
	this->serverName = serverName;
	this->portNumber = portNumber;
	this->isConnected = false;
	this->ssl_ctx = NULL;
	this->conn = NULL;
	this->bio = NULL;
	this->sessionId = NULL;
	this->handshakes = HANDSHAKES_CNT;

	/*Load Client config*/
	initTLS(tcNo);
	loadClientKeys(cipherType);

	runTestCase("Client - Running test Case", testCaseNames[testCaseNo]);

}

/*****************************************************************************
 * Function: loadClientKeys
 * Parameters: cipher_t
 * Return type: void
 * Description: Load the client side certificates, private keys, server CAs
 * 				and ciphersuites
 * **************************************************************************/
void SocketClient::loadClientKeys(cipher_t cipherType){

	if(ECDHE_ECDSA256_X25519 == cipherType || ECDHE256_ECDSA256 == cipherType){

		this->clientCertKey = ECDSA_CLIENT_CERT_KEY_PRIME256V1;
		this->serverCA = EC_PRIME256V1_SERVER_CA;
		this->cipherSuite = ECDSA256_ECDHE256;

	}else if(ECDHE_RSA2048_X25519 == cipherType || ECDHE256_RSA2048 == cipherType){

		this->clientCertKey = RSA_CLIENT_CERT_KEY_2048;
		this->serverCA = RSA2048_SERVER_CA;
		this->cipherSuite = RSA2048_ECDHE256;

	}else if(DHE2048_RSA2048 == cipherType){

		this->clientCertKey = RSA_CLIENT_CERT_KEY_2048;
		this->serverCA = RSA2048_SERVER_CA;
		this->cipherSuite = RSA2048_DHE2048;

	}else if(DHE1024_RSA2048 == cipherType){

		this->clientCertKey = RSA_CLIENT_CERT_KEY_2048;
		this->serverCA = RSA2048_SERVER_CA;
		this->cipherSuite = RSA2048_DHE1024;

	}else if(RSA_3072 == cipherType){

		this->clientCertKey = RSA_CLIENT_CERT_KEY_3072;
		this->serverCA = RSA3072_SERVER_CA;
		this->cipherSuite = RSA3072;

	}else if(RSA_2048 == cipherType){

		this->clientCertKey = RSA_CLIENT_CERT_KEY_2048;
		this->serverCA = RSA2048_SERVER_CA;
		this->cipherSuite = RSA2048;

	}else if(TLS1_3_ECDHE_ECDSA256_X25519 == cipherType || TLS1_3_ECDHE256_ECDSA256 == cipherType){

		this->clientCertKey = ECDSA_CLIENT_CERT_KEY_PRIME256V1;
		this->serverCA = EC_PRIME256V1_SERVER_CA;
		this->cipherSuite = TLS1_3_AES128;

	}else if(TLS1_3_ECDHE_RSA2048_X25519 == cipherType || TLS1_3_ECDHE256_RSA2048 == cipherType){

		this->clientCertKey = RSA_CLIENT_CERT_KEY_2048;
		this->serverCA = RSA2048_SERVER_CA;
		this->cipherSuite = TLS1_3_AES128;
	}

}

/*****************************************************************************
 * Function: connectToServer
 * Parameters: NA
 * Return type: int
 * Description: Initialize/load the connection environment with server and call
 * 				TCP/SSL connect function (sslTcpConnect())
 * 				Return 0 when successfull
 * 				exit otherwise
 * **************************************************************************/
int SocketClient::connectToServer(){

	/*Initialization
	 ** (1)Register SSL/TLS ciphers and digests
	 ** (2)Load Opessl error Strings*/
	init_OpenSSL();

	/*Creating a new SSL context object*/
	ssl_ctx = SSL_CTX_new(TLS_client_method());
	SSL_CTX_set_max_proto_version(ssl_ctx, maxTlsVersion);
	SSL_CTX_set_min_proto_version(ssl_ctx, minTlsVersion);

	if(noSessionTickets)
	SSL_CTX_set_options(this->ssl_ctx, SSL_OP_NO_TICKET);

	if(NULL == ssl_ctx){
		fail("SocketClient.cpp : ssl_ctx object creation failed"); perror("");
	}else{
		pass("SocketClient.cpp : ssl Context created successfully");
	}


	if (SSL_CTX_set_cipher_list(ssl_ctx, this->cipherSuite.c_str()) != 1){
	   perror("SocketCLient.cpp : Unable to set cipher list");
	}else{
		cipherAll("Client loaded Cipher : ", this->cipherSuite.c_str());
	}

	if(ssl_ctx){
		SSL_CTX_set_session_cache_mode(ssl_ctx, SSL_SESS_CACHE_CLIENT
											| SSL_SESS_CACHE_NO_INTERNAL_STORE);
		SSL_CTX_sess_set_new_cb(ssl_ctx, new_session_cb);
	}


	/* Load the client certificate into the SSL_CTX structure */
	if (SSL_CTX_use_certificate_file(ssl_ctx, this->clientCertKey.c_str(), SSL_FILETYPE_PEM) <= 0){
		ERR_print_errors_fp(stderr);
		exit(1);
	}


	/* Load the private-key corresponding to the client certificate */
	if (SSL_CTX_use_PrivateKey_file(ssl_ctx, this->clientCertKey.c_str(), SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}


	/*Load CA certificate in ssl-ctx structure*/
	if(!SSL_CTX_load_verify_locations(ssl_ctx, this->serverCA.c_str(), NULL)){
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	SSL_CTX_set_verify(ssl_ctx,SSL_VERIFY_PEER,NULL);
	SSL_CTX_set_verify_depth(ssl_ctx,1);

	/*Server certificate is authenticated*/
	//pass("SocketClient.cpp : Server certificate Authenticated");
	//Connect to the server
	sslTcpConnect();
	return 0;
}

/*****************************************************************************
 * Function: sslTcpConnect
 * Parameters: NA
 * Return type: int
 * Description: perform TCP and SSL connect with the server
 * 				return 0 when successful
 * 				exit with error message otherwise
 * **************************************************************************/
int SocketClient::sslTcpConnect(){

	/*Attaching the SSL connection to the Socket*/
	if((this->conn = SSL_new(this->ssl_ctx)) == NULL){
		perror("SocketClient.cpp : create new SSL failed ");
		exit(1);
	}

	/*Try to resume session*/

	if(sessResume){
		if(resumeInput){
			SSL_SESSION *sess;
			BIO *stmp = BIO_new_file(sess_file, "r");
			if (!stmp) {
				BIO_printf(bio_err, "Can't open session file %s\n", sess_file);
				ERR_print_errors(bio_err);
			}
			sess = PEM_read_bio_SSL_SESSION(stmp, NULL, 0, NULL);
			BIO_free(stmp);
			if (!sess) {
				BIO_printf(bio_err, "Can't open session file %s\n", sess_file);
				ERR_print_errors(bio_err);
			}
			if (!SSL_set_session(this->conn, sess)) {
				BIO_printf(bio_err, "Can't set session\n");
				ERR_print_errors(bio_err);
			}
			SSL_SESSION_free(sess);
			/*if(FALSE == TLSv1_3){
				if(this->sessionId != NULL){
					SSL_set_session(this->conn, this->sessionId);
					SSL_SESSION_free(this->sessionId);
				}
			}*/
			cout << "Resumption Code is activated" << endl;
		}

		/*Another way of resumption*/
		/*
		if(this->sessionId != NULL){
			SSL_set_session(this->conn, this->sessionId);
			SSL_SESSION_free(this->sessionId);
		}
		*/
	}



	/*Load Pre Shared Session in case of TLS 1_3*/
	if(pskTlsV1_3){
		char *psksessf = sess_file;

		if (psksessf != NULL) {
			BIO *stmp = BIO_new_file(psksessf, "r");

			if (stmp == NULL) {
				BIO_printf(bio_err, "Can't open PSK session file %s\n", psksessf);
				ERR_print_errors(bio_err);
				//goto end;
			}
			psksess = PEM_read_bio_SSL_SESSION(stmp, NULL, 0, NULL);
			BIO_free(stmp);
			if (psksess == NULL) {
				BIO_printf(bio_err, "Can't read PSK session file %s\n", psksessf);
				ERR_print_errors(bio_err);
				//goto end;
			}

			//SSL_SESSION_print(bio_err, psksess);
			//BIO_printf(bio_err,"");
		}

		if (psk_key != NULL || psksess != NULL)
			SSL_set_psk_use_session_callback(this->conn, psk_use_session_cb);
	}

	/****Establish TCP connection****/
	/*Setting up BIO*/
	bio = BIO_new_connect((this->serverName + ":" + this->portNumber).c_str());
	if(!bio)
		int_error("Error creating connection BIO");
	struct timespec st1, st2;
	clock_gettime(CLOCK_MONOTONIC_RAW, &st1);
	if(BIO_do_connect(bio) <= 0){
		fail("SocketClient.cpp : TCP connection failed");
	}else{
		pass("SocketClient.cpp : TCP connection successful");
		clock_gettime(CLOCK_MONOTONIC_RAW, &st2);
		uint64_t delta_us = (st2.tv_sec - st1.tv_sec) * 1000000 + (st2.tv_nsec - st1.tv_nsec) / 1000;
		//time("SocketClient.cpp : TCP conn time : ", delta_us);

	}

	/*set the file descriptor socket-fd as the input/output facility for the TLS/SSL*/
	SSL_set_bio(conn, bio, bio);

	/*SocketClient.cpp : Time Measurement for SSL connection*/
	struct timespec start, end;
	struct timespec stCpu, eCpu;
	/*struct rusage stCpu; struct rusage eCpu;
	if(getrusage(RUSAGE_SELF, &stCpu) == -1){
		perror("SocketServer.cpp : StartCPU Usage not fetched");
	}*/
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &stCpu);
	clock_gettime(CLOCK_MONOTONIC_RAW, &start); //start time

	/*Perform the SSL handshake*/
	if(SSL_connect(conn) != 1){
		fail("SocketClient.cpp : SSL connect failed"); perror("");
		ERR_print_errors_fp(stderr);
		SSL_clear(conn);
		exit(1);
	}else{
		this->isConnected = true;
		pass("SocketClient.cpp : SSL_connect successful");
	}
	clock_gettime(CLOCK_MONOTONIC_RAW, &end); //End time
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &eCpu);
	/*if(getrusage(RUSAGE_SELF, &eCpu) == -1){
		perror("SocketServer.cpp : EndCPU Usage not fetched");
	}*/
	/*-------------------------------------------- Printing the time taken for handshake -------------------------------------*/
	uint64_t delta_us = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_nsec - start.tv_nsec) / 1000;
	time("SocketClient.cpp : Handshake time : ", delta_us);
	/*uint64_t delta_cpu_user_us = (eCpu.ru_utime.tv_sec - stCpu.ru_utime.tv_sec) * 1000000 + (eCpu.ru_utime.tv_usec - stCpu.ru_utime.tv_usec);
	cpu("SocketServer.cpp : User CPU time : ", delta_cpu_user_us);
	uint64_t delta_cpu_sys_us = (eCpu.ru_stime.tv_sec - stCpu.ru_stime.tv_sec) * 1000000 + (eCpu.ru_stime.tv_usec - stCpu.ru_stime.tv_usec);
	cpu("SocketServer.cpp : System CPU time : ", delta_cpu_sys_us);*/
	uint64_t delta_cpu_us = (eCpu.tv_sec - stCpu.tv_sec) * 1000000 + (eCpu.tv_nsec - stCpu.tv_nsec) / 1000;
	cpu("SocketClient.cpp : CPU time : ", delta_cpu_us);
	/*------------------------------------------------------------------------------------------------------------------------*/
	cipher("SocketClient.cpp :  Client Used Cipher : ", SSL_get_cipher(conn));

	/*Save the session Id*/
	/*if(FALSE == TLSv1_3){
		if(this->conn != NULL){
				this->sessionId = SSL_get1_session(this->conn);
				SSL_SESSION_free(this->sessionId);
		}
	}*/
	if(tlsV1_3)
		SSL_read(this->conn, NULL, 0);

	/*Log the latency and cpu utilization values in the clientLogFile*/
	clientOpFile << delta_us << "," << delta_cpu_us << "\n";


	//SSL_CTX_get_client_CA_list(this->ssl_ctx);
	return 0;
}

/*****************************************************************************
 * Function: send
 * Parameters: string
 * Return type: int
 * Description: send message to the server
 * 				return 0 on success, -1 on failure
 * **************************************************************************/
int SocketClient::send(std::string message){
	const char* writeBuffer = message.data();
	int length = message.length();
	int n = SSL_write(this->conn, writeBuffer, length);
	if(n < 0){
		perror("SocketClient.cpp : Error writing message from the client");
		return -1;
	}
	return 0;
}

/*****************************************************************************
 * Function: receive
 * Parameters: size
 * Return type: string
 * Description: read the size number of bytes from the buffer
 * 				when connected to the server
 * **************************************************************************/
string SocketClient::receive(int size=1024){
	char readBuffer[size];
	int n = SSL_read(this->conn, readBuffer, sizeof(readBuffer));
	cout << "Value of N on the client side is " << n << endl;
	if(n<0){
		perror("SocketClient.cpp : error reading from socket");
	}
	return string(readBuffer);	
}

/*****************************************************************************
 * Function: sslTcpClosure
 * Parameters: NA
 * Return type: int
 * Description: close Tcp and SSL connection
 * 				do not shut down the connection context object
 * **************************************************************************/
int SocketClient::sslTcpClosure(){
	if (this->conn){
		SSL_shutdown(this->conn);
		this->conn = NULL;
	}
	if(this->bio){
		BIO_free(this->bio);
		this->conn = NULL;
	}
	cout << endl;
	return 0;
}

/*****************************************************************************
 * Function: disconnectFromServer
 * Parameters: NA
 * Return type: int
 * Description: disconnect from the server, shut down the SSL context
 * **************************************************************************/
int SocketClient::disconnectFromServer(){
	this->isConnected = false;
	/*free the SSL connections*/
	SSL_CTX_free(ssl_ctx);
	return 0;
}

/*****************************************************************************
 * Function: ~SocketClient
 * Parameters: NA
 * Return type: NA
 * Description: Destructor function for the SocketClient class
 * **************************************************************************/
SocketClient::~SocketClient(){

	if(this->isConnected == true){
		disconnectFromServer();
	}
}
