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
bool resumeInput = TRUE; bool sessSaved = false;
static SSL_SESSION *psksess = NULL;
BIO * bio_err = BIO_new_fp(stderr,0x00 | (((1 | 0x8000) & 0x8000) == 0x8000 ? 0x10 : 0));

/* Default PSK identity and key */
static char *psk_identity = "Client_identity";
bool writeData = false; bool earlyDataWrite = false; bool normalData = false; bool readData = false;

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
		/*if(TRUE){
			fprintf(stderr,"SocketClient.cpp: Session is saved on client Side");
			SSL_SESSION_print_keylog(bio_err, sess);
			BIO_printf(bio_err,"");
		}*/
		sessSaved = true;
		pass("SocketClient.cpp : Session is cached on client side");
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

	/*load the cipher to be used*/
	if (SSL_CTX_set_cipher_list(ssl_ctx, this->cipherSuite.c_str()) != 1){
	   perror("SocketCLient.cpp : Unable to set cipher list");
	}else{
		//cipherAll("Client loaded Cipher : ", this->cipherSuite.c_str());
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

	/*Call TCP and SSL connect*/
	writeData = false; earlyDataWrite = false; normalData = false; readData = false;sessSaved = false;
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

	/*For Time/CPU measurements, start a clock at the beginning just after the TCP connect and then
	 * find out the latency and utilization time-stamps post early data write, SSL_connect and SSL_write*/

	/*SocketClient.cpp : Time Measurement for SSL connection*/
	struct timespec stTime, eEarlyDataTime, eConnectTime, eWriteTime, eReadTime;
	struct timespec stCpu, eEarlyDataCpu, eConnectCpu, eWriteCpu, eReadCpu;
	struct rusage startCpuTime; struct rusage endCpuTime; struct rusage endReadCpuTime;

	/*Start the clock - time-stamp for initial time and CPU*/
	GET_TIME(stTime); GET_CPU2(startCpuTime); GET_CPU(stCpu);


	/****Establish TCP connection****/
	/*Setting up BIO*/
	bio = BIO_new_connect((this->serverName + ":" + this->portNumber).c_str());
	if(!bio)
		int_error("Error creating connection BIO");
	if(BIO_do_connect(bio) <= 0){
		fail("SocketClient.cpp : TCP connection failed");
	}else{
		pass("SocketClient.cpp : TCP connection successful");

	}
	/*Disabling Nagle's algorithm*/
	if(DISABLE_NAGLE){
		int sock;
		BIO_get_fd(bio, &sock);
		int flag = 1;
		int result = setsockopt(sock,            /* socket affected */
				IPPROTO_TCP,     /* set option at TCP level */
				TCP_NODELAY,     /* name of option */
				(char *) &flag,  /* the cast is historical
		                                                         cruft */
				sizeof(int));    /* length of option value */
		if (result < 0){
			perror("Nagle's algorithm disable failed");
		}else{
			cout << "Nagle's algorithm is disabled" << endl;
		}
	}

	/*Attaching the SSL connection to the Socket*/
	if((this->conn = SSL_new(this->ssl_ctx)) == NULL){
		perror("SocketClient.cpp : create new SSL failed ");
		exit(1);
	}

	/*set the file descriptor socket-fd as the input/output facility for the TLS/SSL*/
	SSL_set_bio(conn, bio, bio);

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
			//SSL_SESSION_print_keylog(bio_err, sess);
			//BIO_printf(bio_err,"");
			SSL_SESSION_free(sess);
			/*if(FALSE == TLSv1_3){
				if(this->sessionId != NULL){
					SSL_set_session(this->conn, this->sessionId);
					SSL_SESSION_free(this->sessionId);
				}
			}*/
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

	/*Try sending early data*/
	if(READ_WRITE_TEST && earlyData){
		if(writeData == false){
			if(0 == sendEarlyData()){
				/*Time-stamps ---- 1*/
				GET_TIME(eEarlyDataTime); GET_CPU(eEarlyDataCpu);
				writeData = true; earlyDataWrite = true;
				pass("SocketClient.cpp : Early Data Write Success");
			}else{
				fail("SocketClient.cpp : Early Data Write Failed");
			}
		}
	}

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

	/*Time-stamps ---- 2*/
	GET_TIME(eConnectTime); GET_CPU2(endCpuTime); GET_CPU(eConnectCpu);

	if(tlsV1_3 && (false == sessSaved)) /*This is important for session caching on client side in TLS 1.3*/
		SSL_read(this->conn, NULL, 0);

	//SSL_CTX_get_client_CA_list(this->ssl_ctx);
	/*check if early data was accepted*/
	if (SSL_EARLY_DATA_ACCEPTED != SSL_get_early_data_status(this->conn)){
		writeData = false; earlyDataWrite=false;
	}

	if(READ_WRITE_TEST){
		if(false == writeData){
			/*write something to the socket*/
			if(send() == 0){
				pass("SocketClient.cpp : Data Write Success");
				writeData = true; normalData = true;
				/*Time-stamps ---- 3*/
				GET_TIME(eWriteTime); GET_CPU(eWriteCpu);
			}else{
				fail("SocketClient.cpp : Data Write Failed");
			}

		}
	}

	/*if data is not read yet, perform a read*/
	if(false == readData){
		if(receive(BUFFSIZE) == 0){
			/*Time-stamps ---- 4*/
			GET_TIME(eReadTime); GET_CPU(eReadCpu); GET_CPU2(endReadCpuTime);
			readData = true;
			pass("SocketClient.cpp : Data Read Success");
		}else{
			fail("SocketClient.cpp : Data Read Failed");
		}
	}


	/*Enabling Nagle's algorithm*/
	if(DISABLE_NAGLE){
		int sock;
		BIO_get_fd(bio, &sock);
		int flag = 0;
		int result = setsockopt(sock,            /* socket affected */
				IPPROTO_TCP,     /* set option at TCP level */
				TCP_NODELAY,     /* name of option */
				(char *) &flag,  /* the cast is historical
			                                                         cruft */
				sizeof(int));    /* length of option value */
		if (result < 0){
			perror("Nagle's algorithm enable failed");
		}else{
			cout << "Nagle's algorithm is enabled" << endl;
		}
	}

	/*-------------------------------------------- Printing the time taken for handshake -------------------------------------*/
	if(READ_WRITE_TEST && earlyData && earlyDataWrite){
		/*Latency for Early Data read operation*/
		uint64_t delta_eData_us = timeDiff("SocketClient.cpp : Early Data Write Latency -", stTime, eEarlyDataTime);
		/*Measure CPU usage for Early Data read operation*/
		uint64_t delta_eData_cpu_us = cpuDiff("SocketClient.cpp : Early Data Write CPU Utilization -", stCpu, eEarlyDataCpu);
	}

	/*Latency for accept connection*/
	uint64_t delta_connect_us = timeDiff("SocketClient.cpp : Handshake Latency -", stTime, eConnectTime);
	/*Measure CPU usage time till accept - Generally user CPU time is more than system CPU time*/
	uint64_t delta_connect_cpu_us = cpuDiff("SocketClient.cpp : Handshake CPU Utilization -", stCpu, eConnectCpu);
	uint64_t delta_connect_cpu_user_us = 0; uint64_t delta_connect_cpu_sys_us = 0;
	uint64_t delta_connect_cpu_us_2 = cpuDiffSysUser("SocketClient.cpp : Handshake CPU Utilization -", startCpuTime, endCpuTime, \
													delta_connect_cpu_user_us, delta_connect_cpu_sys_us);

	if(READ_WRITE_TEST && normalData){
		/*Latency for write operation on client*/
		uint64_t delta_write_us = timeDiff("SocketClient.cpp : Data Write Latency -", stTime, eWriteTime);
		/*Measure CPU usage time till write operation*/
		uint64_t delta_write_cpu_us = cpuDiff("SocketClient.cpp : Data Write CPU utilization -", stCpu, eWriteCpu);
	}

	if(READ_WRITE_TEST && readData){
		/*Latency for read operation on client*/
		uint64_t delta_read_us = timeDiff("SocketClient.cpp : Data Read Latency -", stTime, eReadTime);
		/*Measure CPU usage time till read operation*/
		uint64_t delta_read_cpu_us = cpuDiff("SocketClient.cpp : Data Read CPU utilization -", stCpu, eReadCpu);
		uint64_t delta_read_cpu_user_us = 0; uint64_t delta_read_cpu_sys_us = 0;
		uint64_t delta_read_cpu_us_2 = cpuDiffSysUser("SocketClient.cpp : Handshake CPU Utilization -", startCpuTime, endReadCpuTime, \
															delta_read_cpu_user_us, delta_read_cpu_sys_us);
		clientOpFile << delta_connect_us << "," << delta_connect_cpu_us << "," << delta_connect_cpu_user_us << "," << delta_connect_cpu_sys_us << "," <<\
				delta_read_us << "," << delta_read_cpu_us << "," << delta_read_cpu_user_us << "," << delta_read_cpu_sys_us<< "\n";
	}
	/*------------------------------------------------------------------------------------------------------------------------*/


	cipher("SocketClient.cpp :  Client Used Cipher : ", SSL_get_cipher(conn));

	/*Log the latency and cpu utilization values in the clientLogFile*/
	if(READ_WRITE_TEST){
		//do nothing here - data is already logged
	}else{
		clientOpFile << delta_connect_us << "," << delta_connect_cpu_us << "," << delta_connect_cpu_user_us << "," << delta_connect_cpu_sys_us << "\n";
	}



	return 0;
}

/*****************************************************************************
 * Function: send
 * Parameters: string
 * Return type: int
 * Description: send message to the server
 * 				return 0 on success, -1 on failure
 * **************************************************************************/
int SocketClient::send(){
	char writeBuffer[BUFFSIZE];
	memset(writeBuffer, 0x00, BUFFSIZE);
	BIO *edfile = BIO_new_file(DATA_FILE_CLIENT, "r");
	size_t readBytes = 0; int finish = 0;

	if (edfile == NULL) {
			BIO_printf(bio_err, "Cannot open client data file\n");
			return -1;
	}

	while(!finish){

		if(!BIO_read_ex(edfile, writeBuffer, BUFFSIZE, &readBytes)){
			finish = 1;
			break;
		}

		if(SSL_write(this->conn, writeBuffer, readBytes) <= 0){
			perror("SocketClient.cpp : Error writing message from the client");
			return -1;
		}
	}

	BIO_free(edfile);
	return 0;
}

/*****************************************************************************
 * Function: sendEarlyData
 * Parameters: string
 * Return type: int
 * Description: send early data to the server
 * 				return 0 on success, -1 on failure
 * **************************************************************************/
int SocketClient::sendEarlyData(){
	char writeBuffer[BUFFSIZE];
	memset(writeBuffer, 0x00, BUFFSIZE);
	if(earlyData){
		BIO *edfile = BIO_new_file(DATA_FILE_CLIENT, "r");
		size_t readBytes, written;
		int finish = 0;

		if (edfile == NULL) {
			BIO_printf(bio_err, "Cannot open early data file\n");
			return -1;
		}

		while (!finish) {

			if (!BIO_read_ex(edfile, writeBuffer, BUFFSIZE, &readBytes))
				finish = 1;

			while(!SSL_write_early_data(this->conn, writeBuffer, readBytes, &written)){
					switch (SSL_get_error(this->conn, 0)) {
						case SSL_ERROR_WANT_WRITE:
						case SSL_ERROR_WANT_ASYNC:
						case SSL_ERROR_WANT_READ:
							/* Just keep trying - busy waiting */
							continue;
						default:
							BIO_printf(bio_err, "Error writing early data\n");
							return -1;
							break;
					}
			}
		}
		BIO_free(edfile);
		if(written != readBytes){
			fail("SocketClient.cpp : Early Send Data Failed");
			return -1;
		}
	}
	return 0;
}

/*****************************************************************************
 * Function: receive
 * Parameters: size
 * Return type: int
 * Description: read the size number of bytes from the buffer
 * 				when connected to the server
 * **************************************************************************/
int SocketClient::receive(int size){
	char readBuffer[size];
	memset(readBuffer, 0x00, BUFFSIZE);
	int n = SSL_read(this->conn, readBuffer, sizeof(readBuffer));
	if(n<0){
		perror("SocketClient.cpp : error reading from socket");
		return -1;
	}
	return 0;
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
