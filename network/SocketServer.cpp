/********************************************************************
 * Filename : SocketServer.cpp
 * Author: Neetish Pathak (nepathak@paypal.com)
 * Description: 1) contains class implementation of SocketServer class
 * 				2) Callback functions for session info update and use
 ********************************************************************/
/*SocketServer.cpp*/

#include "SocketServer.h"
#include "common.h"
using namespace std;

static simple_ssl_session *first = NULL;
static SSL_SESSION *psksess = NULL;
static char *psk_identity = "Client_identity";
BIO * bio_err = BIO_new_fp(stderr,0x00 | (((1 | 0x8000) & 0x8000) == 0x8000 ? 0x10 : 0));
bool readData = false; bool earlyData = false; bool normalData = false;
/************************************************************************************************/
/*Following functions are for explicit (user enabled) caching on the server side*/
/************************************************************************************************/
/*****************************************************************************
 * Function: app_malloc
 * Parameters: int, const char *
 * Return type: void*
 * Description: reserve space of sz bytes from the heap to store session info
 * **************************************************************************/
void* app_malloc(int sz, const char *what)
{
    void *vp = OPENSSL_malloc(sz);

    if (vp == NULL) {
        BIO_printf(bio_err, "Could not allocate %d bytes for %s\n", sz, what);
        ERR_print_errors(bio_err);
        exit(1);
    }
    return vp;
}

/***************************************************************************************
 * Function: add_session
 * Parameters: SSL *ssl, SSL_SESSION *session
 * Return type: int
 * Description: add/store a session to the linked list of the simple_ssl_session structs
 * *************************************************************************************/
static int add_session(SSL *ssl, SSL_SESSION *session)
{
    simple_ssl_session *sess = (simple_ssl_session*)OPENSSL_malloc(sizeof(simple_ssl_session));
    unsigned char *p;

    SSL_SESSION_get_id(session, &sess->idlen);
    sess->derlen = i2d_SSL_SESSION(session, NULL);
    if (sess->derlen < 0) {
        BIO_printf(bio_err, "Error encoding session\n");
        OPENSSL_free(sess);
        return 0;
    }

    sess->id = (unsigned char *)OPENSSL_memdup(SSL_SESSION_get_id(session, NULL), sess->idlen);
    sess->der = (unsigned char *)app_malloc(sess->derlen, "get session buffer");
    if (!sess->id) {
        BIO_printf(bio_err, "Out of memory adding to external cache\n");
        OPENSSL_free(sess->id);
        OPENSSL_free(sess->der);
        OPENSSL_free(sess);
        return 0;
    }
    p = sess->der;

    /* Assume it still works. */
    if (i2d_SSL_SESSION(session, &p) != sess->derlen) {
        BIO_printf(bio_err, "Unexpected session encoding length\n");
        OPENSSL_free(sess->id);
        OPENSSL_free(sess->der);
        OPENSSL_free(sess);
        return 0;
    }

    sess->next = first;
    first = sess;
    BIO_printf(bio_err, "New session added to external cache\n");
    return 0;
}

/*****************************************************************************
 * Function: get_session
 * Parameters: SSL *ssl, const unsigned char *id, int idlen, int *do_copy
 * Return type: SSL_SESSION
 * Description: retrieve a session from the stored sessions in the
 * 				linked list of simple_ssl_structs
 * **************************************************************************/
static SSL_SESSION *get_session(SSL *ssl, const unsigned char *id, int idlen,
                                int *do_copy)
{
    simple_ssl_session *sess;
    *do_copy = 0;
    for (sess = first; sess; sess = sess->next) {
        if (idlen == (int)sess->idlen && !memcmp(sess->id, id, idlen)) {
            const unsigned char *p = sess->der;
            BIO_printf(bio_err, "Lookup session: cache hit\n");
            return d2i_SSL_SESSION(NULL, &p, sess->derlen);
        }
    }
    BIO_printf(bio_err, "Lookup session: cache miss\n");
    return NULL;
}

/*****************************************************************************
 * Function: del_session
 * Parameters: SSL_CTX *sctx, SSL_SESSION *session
 * Return type: void
 * Description: delete the session  using the session id of the session
 * 				passed in the arguments from the stored sessions in the
 * 				linked list of simple_ssl_structs
 * **************************************************************************/
static void del_session(SSL_CTX *sctx, SSL_SESSION *session)
{
    simple_ssl_session *sess, *prev = NULL;
    const unsigned char *id;
    unsigned int idlen;
    id = SSL_SESSION_get_id(session, &idlen);
    for (sess = first; sess; sess = sess->next) {
        if (idlen == sess->idlen && !memcmp(sess->id, id, idlen)) {
            if (prev)
                prev->next = sess->next;
            else
                first = sess->next;
            OPENSSL_free(sess->id);
            OPENSSL_free(sess->der);
            OPENSSL_free(sess);
            return;
        }
        prev = sess;
    }
}

/*****************************************************************************
 * Function: init_session_cache_ctx
 * Parameters: explicit session caching initialization
 * Return type: void
 * Description: Initialize the session caching
 * **************************************************************************/
static void init_session_cache_ctx(SSL_CTX *sctx)
{
    SSL_CTX_set_session_cache_mode(sctx,
                                   SSL_SESS_CACHE_NO_INTERNAL |
                                   SSL_SESS_CACHE_SERVER);
    SSL_CTX_sess_set_new_cb(sctx, add_session);
    SSL_CTX_sess_set_get_cb(sctx, get_session);
    SSL_CTX_sess_set_remove_cb(sctx, del_session);
}

/*************************************************************************************
 * Function: free_sessions
 * Parameters: void
 * Return type: void
 * Description: free the space allocated for storing the sessions in the linked list
 * *********************************************************************************/
static void free_sessions(void)
{
    simple_ssl_session *sess, *tsess;
    for (sess = first; sess;) {
        OPENSSL_free(sess->id);
        OPENSSL_free(sess->der);
        tsess = sess;
        sess = sess->next;
        OPENSSL_free(tsess);
    }
    first = NULL;
}
/************************************************************************************************/
/********************End of utility functions for explicit session caching***********************/
/************************************************************************************************/


/***********************************************************************
 * Function: psk_find_session_cb
 * Parameters: SSL *ssl, const unsigned char *identity,
               size_t identity_len, SSL_SESSION **sess
 * Return type: int
 * Description: callback function for the session re-use using ext PSK
 * 				with TLS 1.3 (referenced from s_server.c in openssl code)
 * *********************************************************************/
static int psk_find_session_cb(SSL *ssl, const unsigned char *identity,
                               size_t identity_len, SSL_SESSION **sess)
{
    SSL_SESSION *tmpsess = NULL;
    unsigned char *key;
    long key_len;
    const SSL_CIPHER *cipher = NULL;
    if (strlen(psk_identity) != identity_len
            || memcmp(psk_identity, identity, identity_len) != 0)
        return 0;

    if (psksess != NULL) {

    	if(FALSE){
    		cout << "SocketServer.cpp: Session re-use using external(session file) on the server side" << endl;
    	}

        SSL_SESSION_up_ref(psksess);
        *sess = psksess;
        return 1;
    }

    key = OPENSSL_hexstr2buf(psk_key, &key_len);
    if (key == NULL) {
        BIO_printf(bio_err, "Could not convert PSK key '%s' to buffer\n",
                   psk_key);
        return 0;
    }

    if (key_len == EVP_MD_size(EVP_sha256()))
        cipher = SSL_CIPHER_find(ssl, tls13_aes128gcmsha256_id);
    else if(key_len == EVP_MD_size(EVP_sha384()))
        cipher = SSL_CIPHER_find(ssl, tls13_aes256gcmsha384_id);

    if (cipher == NULL) {
        /* Doesn't look like a suitable TLSv1.3 key. Ignore it */
        OPENSSL_free(key);
        return 0;
    }

    tmpsess = SSL_SESSION_new();
    if (tmpsess == NULL
            || !SSL_SESSION_set1_master_key(tmpsess, key, key_len)
            || !SSL_SESSION_set_cipher(tmpsess, cipher)
            || !SSL_SESSION_set_protocol_version(tmpsess, SSL_version(ssl))) {
        OPENSSL_free(key);
        return 0;
    }
    OPENSSL_free(key);
    *sess = tmpsess;
    if(FALSE){
    	cout << "SocketServer.cpp: Session re-use using external PSK code on the server side" << endl;
    }
    return 1;
}
/***********************************************************************
 * Function: SocketServer
 * Parameters: std::string portNumber, test_Case_Num tcNo, cipher_t cipherType
 * Return type: NA (constructor)
 * Description: SocketServer constructor
 * 				Initialize the server side attributes
 * *********************************************************************/
SocketServer::SocketServer(std::string portNumber, test_Case_Num tcNo, cipher_t cipherType){

	this->portNumber = portNumber;
	this->clientConnected = false;
	this->ssl_ctx = NULL;
	this->conn = NULL;
	this->bio = NULL;
	this->bioClient = NULL;

	/*load Server config*/
	initTLS(tcNo);
	loadServerKeys(cipherType);
	runTestCase("Server - Running test Case", testCaseNames[testCaseNo]);
}

/***********************************************************************
 * Function: loadServerKeys
 * Parameters: cipher_t cipherType
 * Return type: void
 * Description: load server side certificates, private keys and client CA
 * 				dh paramters, ec paramters
 * *********************************************************************/
void SocketServer::loadServerKeys(cipher_t cipherType){

	if(ECDHE_ECDSA256_X25519 == cipherType || ECDHE256_ECDSA256 == cipherType){

			this->serverCertKey = ECDSA_SERVER_CERT_KEY_PRIME256V1;
			this->clientCA = EC_PRIME256V1_CLIENT_CA;
			this->dhParams = DHPARAMS_2048;
			this->ecParams = ECPARAMS_PRIME256V1;
			this->enableDhParams = false;
			this->enableEcParams = ECDHE256_ECDSA256 == cipherType?true:false;

		}else if(ECDHE_RSA2048_X25519 == cipherType || ECDHE256_RSA2048 == cipherType){
			this->serverCertKey = RSA_SERVER_CERT_KEY_2048;
			this->clientCA = RSA2048_CLIENT_CA;
			this->dhParams = DHPARAMS_2048;
			this->ecParams = ECPARAMS_PRIME256V1;
			this->enableDhParams = false;
			this->enableEcParams = ECDHE256_RSA2048 == cipherType?true:false;

		}else if(DHE2048_RSA2048 == cipherType || DHE1024_RSA2048 == cipherType){
			this->serverCertKey = RSA_SERVER_CERT_KEY_2048;
			this->clientCA = RSA2048_CLIENT_CA;
			this->dhParams = DHE1024_RSA2048 == cipherType?DHPARAMS_1024:DHPARAMS_2048;
			this->ecParams = ECPARAMS_PRIME256V1;
			this->enableDhParams = true;
			this->enableEcParams = false;

		}else if(RSA_3072 == cipherType){

			this->serverCertKey = RSA_SERVER_CERT_KEY_3072;
			this->clientCA = RSA3072_CLIENT_CA;
			this->dhParams = DHPARAMS_2048;
			this->ecParams = ECPARAMS_PRIME256V1;
			this->enableDhParams = false;
			this->enableEcParams = false;

		}else if(RSA_2048 == cipherType){

			this->serverCertKey = RSA_SERVER_CERT_KEY_2048;
			this->clientCA = RSA2048_CLIENT_CA;
			this->dhParams = DHPARAMS_2048;
			this->ecParams = ECPARAMS_PRIME256V1;
			this->enableDhParams = false;
			this->enableEcParams = false;

		}else if(TLS1_3_ECDHE_ECDSA256_X25519 == cipherType || TLS1_3_ECDHE256_ECDSA256 == cipherType){

			this->serverCertKey = ECDSA_SERVER_CERT_KEY_PRIME256V1;
			this->clientCA = EC_PRIME256V1_CLIENT_CA;
			this->dhParams = DHPARAMS_2048;
			this->ecParams = ECPARAMS_PRIME256V1;
			this->enableDhParams = false;
			this->enableEcParams = TLS1_3_ECDHE256_ECDSA256 == cipherType?true:false;

		}else if(TLS1_3_ECDHE_RSA2048_X25519 == cipherType || TLS1_3_ECDHE256_RSA2048 == cipherType){

			this->serverCertKey = RSA_SERVER_CERT_KEY_2048;
			this->clientCA = RSA2048_CLIENT_CA;
			this->dhParams = DHPARAMS_2048;
			this->ecParams = ECPARAMS_PRIME256V1;
			this->enableDhParams = false;
			this->enableEcParams = TLS1_3_ECDHE256_RSA2048 == cipherType?true:false;

		}
	return;
}

/*****************************************************************
 * Function: got_signal
 * Parameters: int
 * Return Type: void
 * Description: signal handler (when server is interrupted/killed)
 * ***************************************************************/
std::atomic<bool> quit(false);    // signal flag

void got_signal(int)
{
	quit.store(true);
}

/******************************************************************
 * Function: listen
 * Parameters: NA
 * Return Type: int
 * Description: initialize the connection(listening) socket on the
 * 				designated port
 * 				wait for client connections
 * ***************************************************************/
int SocketServer::listen(){

	/*Signal Handling*/
	struct sigaction sa;
	memset( &sa, 0, sizeof(sa) );
	sa.sa_handler = got_signal;
	sigfillset(&sa.sa_mask);
	sigaction(SIGINT,&sa,NULL);

	/*Initialization
	 ** (1)Register SSL/TLS ciphers and digests
	** (2)Load Opessl error Strings*/
	init_OpenSSL();

	/*Creating a new SSL context object*/
	this->ssl_ctx = SSL_CTX_new(TLS_server_method());

	const unsigned char normal_user = '1';
	int admin_user = 2;

	/*Configuration for session tickets*/
	if(noSessionTickets)
	SSL_CTX_set_options(this->ssl_ctx, SSL_OP_NO_TICKET);

	/*set minimum and maximum TLS versions*/
	SSL_CTX_set_max_proto_version(ssl_ctx, maxTlsVersion);
	SSL_CTX_set_min_proto_version(ssl_ctx, minTlsVersion);

	if(NULL == ssl_ctx){
		fail("SocketServer.cpp : ssl_ctx object creation failed"); perror("");
	}else{
		pass("SocketServer.cpp : ssl Context created successfully");
	}

	/*Server side session id contect setting*/
	SSL_CTX_set_session_id_context(ssl_ctx, &normal_user, sizeof(normal_user));
	//SSL_CTX_set_session_cache_mode(ssl_ctx, SSL_SESS_CACHE_BOTH);
	//SSL_CTX_set_timeout(ssl_ctx, 600);
	//init_session_cache_ctx(this->ssl_ctx);


	/* Load the client certificate into the SSL_CTX structure */
	if (SSL_CTX_use_certificate_file(ssl_ctx, this->serverCertKey.c_str(), SSL_FILETYPE_PEM) <= 0){
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	/* Load the private-key corresponding to the client certificate */
	if (SSL_CTX_use_PrivateKey_file(ssl_ctx, this->serverCertKey.c_str(), SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	/* Check if the client certificate and private-key matches */
	if (!SSL_CTX_check_private_key(ssl_ctx)) {
		perror("SocketServer.cpp : Private key does not match the certificate public key\n");
		exit(1);
	}

	/*Load CA certificate in ssl-ctx structure*/
	if(!SSL_CTX_load_verify_locations(ssl_ctx, this->clientCA.c_str(), NULL)){
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	SSL_CTX_set_verify(ssl_ctx,SSL_VERIFY_PEER,NULL);
	SSL_CTX_set_verify_depth(ssl_ctx,1);
	/*Server certificate is authenticated*/
	pass("SocketServer.cpp : Client certificate Authenticated");

	/*load Dh parameters - important when DHE type ciphers is used*/
	if(this->enableDhParams){
		//DH
		DH *dh;
		BIO *bio;
		bio = BIO_new_file(this->dhParams.c_str(), "r");
		if(!bio){
			fail("SocketServer.cpp : Unable to read the DH params from dhparams file");
			ERR_error_string(ERR_get_error(), NULL);
		}

		dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
		BIO_free(bio);

		if(dh){
			pass("dh Read successfully");
			SSL_CTX_set_tmp_dh(ssl_ctx, dh);
			DH_free(dh);
		}
	}

	/*load EC parameters - important when ECDHE type cipher is used*/
	if(this->enableEcParams){
		/*ECDH*/
		EC_KEY *ecdh = NULL;
		EC_GROUP *ecg = NULL;
		BIO *bio;
		bio = BIO_new_file(this->ecParams.c_str(), "r");


		if(!bio){
			fail("SocketServer.cpp : Unable to read ECDH params from dhparams file");
			ERR_error_string(ERR_get_error(), NULL);
		}

		ecg = PEM_read_bio_ECPKParameters(bio, NULL, NULL, NULL);
		BIO_free(bio);

		if(ecg){
			int nid = EC_GROUP_get_curve_name(ecg);

			if(!nid){
				fail("SocketServer.cpp : Unable to find the specified curve name");
			}

			ecdh = EC_KEY_new_by_curve_name(nid);
			EC_KEY_set_asn1_flag(ecdh, OPENSSL_EC_NAMED_CURVE);
			pass("EC get curve is successful");

		}

		/*Use prime256v1 by default*/
		if(ecdh == NULL){
			fail("No name is specified for ecdh. assigning default name NID_X9_62_prime256v1");
			ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
			EC_KEY_set_asn1_flag(ecdh, OPENSSL_EC_NAMED_CURVE);

		}

		SSL_CTX_set_tmp_ecdh(ssl_ctx,ecdh);
		EC_KEY_free(ecdh);

	}

	struct timespec start, end, endWrite;
	/*Establish a TCP connection*/
	/*listening socket*/
	bio = BIO_new_accept((this->portNumber).c_str());

	if(!bio)
		int_error("SocketServer.cpp : Error setting accept");
	//BIO_set_nbio(bio, 200);
	if(BIO_do_accept(bio) <= 0)
		int_error("SicketServer.cpp : Error binding the server Socket");

	//int loop = HANDSHAKES_CNT;
	for(;;){
		readData = false; earlyData = false; normalData = false;
		if(BIO_do_accept(bio) <= 0){
			if(quit.load()){return 0;}
			fail("SocketServer.cpp : Error on accepting TCP connection");
			int_error("TCP connection failure");
		}else{
			pass("SocketServer.cpp : TCP connection successful");
		}
		this->bioClient = BIO_pop(bio);

		/*Attach the SSL connection to socket*/
		conn = SSL_new(ssl_ctx);
		if(NULL == conn){
			fail("SocketServer.cpp : create new SSL structure failed");
		}

		SSL_set_bio(conn, this->bioClient, this->bioClient);
		

		/*Load Pre Shared Session in case of TLS 1_3*/
		if(pskTlsV1_3){
			char *psksessf =  sess_file;
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

			}

			if (psk_key != NULL || psksess != NULL)
				SSL_set_psk_find_session_callback(this->conn, psk_find_session_cb);
		}

		/*For Time/CPU measurements, start a clock at the beginning just after the TCP connect and then
				 * find out the latency and utilization time-stamps post early data read, SSL_accept and SSL_read*/

		struct timespec stTime, eEarlyDataTime, eAcceptTime, eReadTime;
		struct timespec stCpu, eEarlyDataCpu, eAcceptCpu, eReadCpu;
		struct rusage startCpuTime; struct rusage endCpuTime;

		/*Start the clock - time-stamp for initial time and CPU*/
		GET_TIME(stTime); GET_CPU2(startCpuTime); GET_CPU(stCpu);


		if(EARLY_DATA && !readData){
			/*Try and receive early data if any (Applicable for TLS 1.3 - should fail for TLS version <= TLS1.2)*/
			std::string readBuf;
			if(0 == receiveEarlyData(1024, readBuf)){
				pass("Early Data read Success");
				readData = true; earlyData = true;
				cout << "Early Received Data is " << readBuf << endl;
				/*Time-stamps ---- 1*/
				GET_TIME(eEarlyDataTime); GET_CPU(eEarlyDataCpu);
			}else{
				fail("Early Data read Fail");
			}
		}

		/*SSL accept call to establish the connection Main step to establish SSL connection*/
		if(SSL_accept(this->conn) != 1){
			fail("SocketServer.cpp : SSL accept Fail"); perror("");
			ERR_print_errors_fp(stderr);
			SSL_clear(conn);
			exit(1);
		}else{
			pass("SocketServer.cpp : SSL accept is successful");
		}

		/*Time-stamps ---- 2*/
		GET_TIME(eAcceptTime); GET_CPU2(endCpuTime); GET_CPU(eAcceptCpu);

		if(READ_WRITE_TEST && !readData){
			/*Try and Read any data from the client*/
			std::string readBuf;
			if(0 == receive(1024, readBuf)){
				pass("Data Read success");
				normalData = true; readData = true;
				cout << "Received Data is " << readBuf << endl;
				/*Time-stamps ---- 3*/
				GET_TIME(eReadTime); GET_CPU(eReadCpu);
			}else{
				fail("Data Read fail");
			}
		}

		if(READ_WRITE_TEST && EARLY_DATA && earlyData){
			/*Latency for Early Data read operation*/
			uint64_t delta_eData_us = timeDiff("SocketServer.cpp : Early Data Read Latency -", stTime, eEarlyDataTime);
			/*Measure CPU usage for Early Data read operation*/
			uint64_t delta_eData_cpu_us = cpuDiff("SocketServer.cpp : Early Data Read CPU Utilization -", stCpu, eEarlyDataCpu);
		}

		/*Latency for accept connection*/
		uint64_t delta_accept_us = timeDiff("SocketServer.cpp : Handshake Latency -", stTime, eAcceptTime);
		/*Measure CPU usage time till accept - Generally user CPU time is more than system CPU time*/
		uint64_t delta_accept_cpu_us = cpuDiff("SocketServer.cpp : Handshake CPU Utilization -", stCpu, eAcceptCpu);
		uint64_t delta_connect_cpu_user_us = 0; uint64_t delta_connect_cpu_sys_us = 0;
		uint64_t delta_connect_cpu_us_2 = cpuDiffSysUser("SocketServer.cpp : Handshake CPU Utilization -", startCpuTime, endCpuTime, \
															delta_connect_cpu_user_us, delta_connect_cpu_sys_us);

		if(READ_WRITE_TEST && normalData){
			/*Latency for read operation on server*/
			uint64_t delta_read_us = timeDiff("SocketServer.cpp : Read Latency -", stTime, eReadTime);
			/*Measure CPU usage time till read operation*/
			uint64_t delta_read_cpu_us = cpuDiff("SocketServer.cpp : Read CPU utilization -", stCpu, eReadCpu);
		}


		/*The selected Cipher-suite by the server is */
		if(DEBUG)
		cipher("SocketServer.cpp :  Server selected Cipher : ", SSL_get_cipher(conn));

		SSL_shutdown(this->conn);
		BIO_free(this->bioClient);
		this->conn = NULL;
		this->bioClient = NULL;

		/*Write to the output file*/
		if(serverOpFile.is_open()){
			serverOpFile << delta_accept_us << "," << delta_accept_cpu_us <<"," << delta_connect_cpu_user_us << "," << delta_connect_cpu_sys_us << "\n";
		}
		/*Leave one line*/
		cout << endl;

		// loop count is maintained just for the purpose of testing
		//loop--;
		//if(loop <= 0)break;

	}

	return 0;
}

/*****************************************************************************
 * Function: send
 * Parameters: string message
 * Return type: int
 * Description: send message to the connected client
 * **************************************************************************/
int SocketServer::send(std::string message){
	const char* writeBuffer = message.data();
	int length = message.length();
	int n = SSL_write(this->conn, writeBuffer, length);
	if(n < 0){
		perror("SocketServer.cpp : Error on writing to client");
		return -1;
	}else{
		cout << "Written successfully by the server" << endl;
	}
	return n;
}

/*****************************************************************************
 * Function: receive
 * Parameters: int size
 * Return type: string
 * Description: receive the size number of bytes from the connected client
 * **************************************************************************/
int SocketServer::receive(int size, std::string &readBuf){
	char readBuffer[size];
	int n = SSL_read(this->conn, readBuffer, sizeof(readBuffer));
	if(n < 0){
		perror("SocketServer.cpp : error on reading on the server");
		return -1;
	}
	readBuf = string(readBuffer);
	return 0;
}

/*****************************************************************************
 * Function: receiveEarlyData
 * Parameters: int size
 * Return type: int
 * Description: receive Early Data from the client side
 * **************************************************************************/
int SocketServer::receiveEarlyData(int size, std::string &readBuf){
	char readBuffer[1024];
	size_t readBytes = 0;size_t totalBytes = 0;
	int n;
	while(n != SSL_READ_EARLY_DATA_FINISH){
		n =  SSL_read_early_data(this->conn, readBuffer, sizeof(readBuffer), &readBytes);
		switch(n){
			case SSL_READ_EARLY_DATA_ERROR:
						switch (SSL_get_error(this->conn, 0)) {
							case SSL_ERROR_WANT_WRITE:
							case SSL_ERROR_WANT_ASYNC:
							case SSL_ERROR_WANT_READ:
								/* Just keep trying - busy waiting */
								continue;
							default:
								ERR_print_errors(bio_err);
								return -1;
								break;
					   }
				break;
			case SSL_READ_EARLY_DATA_SUCCESS:
				totalBytes += readBytes;
				break;
			case SSL_READ_EARLY_DATA_FINISH:
				totalBytes += readBytes;
				if (totalBytes > 0) {
					readBuf = string(readBuffer);
					return 0;
				}else{
				}
				break;
			default:
				break;
		}

	}
	return -1;
}

/*****************************************************************************
 * Function: ~SocketServer
 * Parameters: NA
 * Return type: NA
 * Description: Destructor function for the SocketServer class
 * **************************************************************************/
SocketServer :: ~SocketServer(){

	BIO_free(this->bio);
	if(this->conn){
		int sd = SSL_get_fd(conn);
		close(sd);
	}

	SSL_CTX_free(ssl_ctx);	
	fprintf(stderr,"\n\033[1;35mServer Shutdown...\033[0m\n");
}
