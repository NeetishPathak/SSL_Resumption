/*SocketClient.cpp*/

#include "SocketClient.h"

using namespace std;
SSL_SESSION *sessionDet = NULL;
char *sess_out = NULL;
bool resumeInput = FALSE;
BIO * bio_err = BIO_new_fp(stderr,0x00 | (((1 | 0x8000) & 0x8000) == 0x8000 ? 0x10 : 0));

static SSL_SESSION *psksess = NULL;
/* Default PSK identity and key */
static char *psk_identity = "Client_identity";


static int psk_use_session_cb(SSL *s, const EVP_MD *md,
                              const unsigned char **id, size_t *idlen,
                              SSL_SESSION **sess)
{
    SSL_SESSION *usesess = NULL;
    const SSL_CIPHER *cipher = NULL;

    if (psksess != NULL) {
        SSL_SESSION_up_ref(psksess);
        usesess = psksess;
    } else {

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


static int new_session_cb(SSL* ssl, SSL_SESSION * sess){


	BIO *stmp = BIO_new_file(SESS_OUT,"w");

	if(stmp == NULL){
		BIO_printf(bio_err,"Error writing session file %s\n",SESS_OUT);
	}else{
		//fprintf(stderr,"Session getting set\n");
		PEM_write_bio_SSL_SESSION(stmp,sess);
		BIO_free(stmp);
		resumeInput = TRUE;
	}

	return 0;

}

SocketClient::SocketClient(string serverName, string portNumber){
	this->serverName = serverName;
	this->portNumber = portNumber;
	this->isConnected = false;
	this->ssl_ctx = NULL;
	this->conn = NULL;
	this->bio = NULL;
	this->sessionId = NULL;
	this->handshakes = HANDSHAKES_CNT;
#if HANDSHAKES_CNT_LOOP
	this->clientOpFile.open(CLIENT_FILENAME,std::ofstream::out);
#endif
}

int SocketClient::connectToServer(){

	/*Initialization
	 ** (1)Register SSL/TLS ciphers and digests
	 ** (2)Load Opessl error Strings*/
	init_OpenSSL();

	/*Creating a new SSL context object*/
	ssl_ctx = SSL_CTX_new(TLS_client_method());
	SSL_CTX_set_max_proto_version(ssl_ctx, MAX_TLS_VERSION);
	SSL_CTX_set_min_proto_version(ssl_ctx, MIN_TLS_VERSION);

	if(NO_SESSION_TICKETS)
	SSL_CTX_set_options(this->ssl_ctx, SSL_OP_NO_TICKET);

	if(NULL == ssl_ctx){
		fail("SocketClient.cpp : ssl_ctx object creation failed"); perror("");
	}else{
		pass("SocketClient.cpp : ssl Context created successfully");
	}


	if (SSL_CTX_set_cipher_list(ssl_ctx, CIPHERSUITE) != 1){
	   perror("SocketCLient.cpp : Unable to set cipher list");
	}else{
		cipherAll("Client loaded Cipher : ", CIPHERSUITE);
	}

	if(ssl_ctx){
		SSL_CTX_set_session_cache_mode(ssl_ctx, SSL_SESS_CACHE_CLIENT
											| SSL_SESS_CACHE_NO_INTERNAL_STORE);
		SSL_CTX_sess_set_new_cb(ssl_ctx, new_session_cb);
	}

	/*Load Pre Shared Session in case of TLS 1_3*/
	if(PRE_SHARED_KEY_TLS1_3)
	if (psk_key != NULL || psksess != NULL)
	        SSL_CTX_set_psk_use_session_callback(ssl_ctx, psk_use_session_cb);


	/* Load the client certificate into the SSL_CTX structure */
	if (SSL_CTX_use_certificate_file(ssl_ctx, CLIENT_CERT_KEY, SSL_FILETYPE_PEM) <= 0){
		ERR_print_errors_fp(stderr);
		exit(1);
	}


	/* Load the private-key corresponding to the client certificate */
	if (SSL_CTX_use_PrivateKey_file(ssl_ctx, CLIENT_CERT_KEY, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}


	/*Load CA certificate in ssl-ctx structure*/
	if(!SSL_CTX_load_verify_locations(ssl_ctx, SERVER_CA, NULL)){
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	SSL_CTX_set_verify(ssl_ctx,SSL_VERIFY_PEER,NULL);
	SSL_CTX_set_verify_depth(ssl_ctx,1);
	/*Server certificate is authenticated*/
	pass("SocketClient.cpp : Server certificate Authenticated");



	return 0;
}

std::pair<uint64_t, double> SocketClient::sslTcpConnect(){

	/*Attaching the SSL connection to the Socket*/
	if((this->conn = SSL_new(ssl_ctx)) == NULL){
		perror("SocketClient.cpp : create new SSL failed ");
		exit(1);
	}

	/*Try to resume session*/
#if SESS_RESUME

		if(resumeInput){
			SSL_SESSION *sess;
			BIO *stmp = BIO_new_file(SESS_OUT, "r");
			if (!stmp) {
				BIO_printf(bio_err, "Can't open session file %s\n", SESS_OUT);
				ERR_print_errors(bio_err);
			}
			sess = PEM_read_bio_SSL_SESSION(stmp, NULL, 0, NULL);
			BIO_free(stmp);
			if (!sess) {
				BIO_printf(bio_err, "Can't open session file %s\n", SESS_OUT);
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
#endif

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
	if(TLSv1_3)
		SSL_read(this->conn, NULL, 0);

#if HANDSHAKES_CNT_LOOP
	clientOpFile << delta_us << "," << delta_cpu_us << "\n";
#endif

	SSL_CTX_get_client_CA_list(this->ssl_ctx);
	pair<uint64_t, double> stats;
	stats.first = delta_us;
	stats.second = (delta_cpu_us);
	return stats;
}

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

string SocketClient::receive(int size=1024){
	char readBuffer[size];
	int n = SSL_read(this->conn, readBuffer, sizeof(readBuffer));
	cout << "Value of N on the client side is " << n << endl;
	if(n<0){
		perror("SocketClient.cpp : error reading from socket");
	}
	return string(readBuffer);	
}

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

int SocketClient::disconnectFromServer(){
	this->isConnected = false;
	/*free the SSL connections*/
	SSL_CTX_free(ssl_ctx);
	return 0;
}

SocketClient::~SocketClient(){
#if HANDSHAKES_CNT_LOOP
	if(this->clientOpFile.is_open())
	this->clientOpFile.close();
#endif
	if(this->isConnected == true){
		disconnectFromServer();
	}
}
