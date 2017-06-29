/*SocketServer.cpp*/

#include "SocketServer.h"
#include "common.h"
using namespace std;

BIO * bio_err = BIO_new_fp(stderr,0x00 | (((1 | 0x8000) & 0x8000) == 0x8000 ? 0x10 : 0));

typedef struct simple_ssl_session_st {
    unsigned char *id;
    unsigned int idlen;
    unsigned char *der;
    int derlen;
    struct simple_ssl_session_st *next;
} simple_ssl_session;

static simple_ssl_session *first = NULL;



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

static void init_session_cache_ctx(SSL_CTX *sctx)
{
    SSL_CTX_set_session_cache_mode(sctx,
                                   SSL_SESS_CACHE_NO_INTERNAL |
                                   SSL_SESS_CACHE_SERVER);
    SSL_CTX_sess_set_new_cb(sctx, add_session);
    SSL_CTX_sess_set_get_cb(sctx, get_session);
    SSL_CTX_sess_set_remove_cb(sctx, del_session);
}

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


SocketServer::SocketServer(std::string portNumber){

	this->portNumber = portNumber;
	this->clientConnected = false;
	this->ssl_ctx = NULL;
	this->conn = NULL;
	this->bio = NULL;
	this->bioClient = NULL;
#if HANDSHAKES_CNT_LOOP
	this->serverOpFile.open(CLIENT_FILENAME,std::ofstream::out);
#endif
}

std::atomic<bool> quit(false);    // signal flag

void got_signal(int)
{
	quit.store(true);
}

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
	SSL_CTX_set_session_id_context(ssl_ctx, &normal_user, sizeof(normal_user));
	//SSL_CTX_set_session_cache_mode(ssl_ctx, SSL_SESS_CACHE_BOTH);
	//SSL_CTX_set_timeout(ssl_ctx, 600);
	//init_session_cache_ctx(this->ssl_ctx);

	if(NO_SESSION_TICKETS)
	SSL_CTX_set_options(this->ssl_ctx, SSL_OP_NO_TICKET);

	SSL_CTX_set_max_proto_version(ssl_ctx, MAX_TLS_VERSION);
	SSL_CTX_set_min_proto_version(ssl_ctx, MIN_TLS_VERSION);

	if(NULL == ssl_ctx){
		fail("SocketClient.cpp : ssl_ctx object creation failed"); perror("");
	}else{
		pass("SocketClient.cpp : ssl Context created successfully");
	}

	/* Load the client certificate into the SSL_CTX structure */
	if (SSL_CTX_use_certificate_file(ssl_ctx, SERVER_CERT_KEY, SSL_FILETYPE_PEM) <= 0){
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	/* Load the private-key corresponding to the client certificate */
	if (SSL_CTX_use_PrivateKey_file(ssl_ctx, SERVER_CERT_KEY, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	/* Check if the client certificate and private-key matches */
	if (!SSL_CTX_check_private_key(ssl_ctx)) {
		perror("SocketServer.cpp : Private key does not match the certificate public key\n");
		exit(1);
	}

	/*Load CA certificate in ssl-ctx structure*/
	if(!SSL_CTX_load_verify_locations(ssl_ctx, CLIENT_CA, NULL)){
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	SSL_CTX_set_verify(ssl_ctx,SSL_VERIFY_PEER,NULL);
	SSL_CTX_set_verify_depth(ssl_ctx,1);
	/*Server certificate is authenticated*/
	pass("SocketServer.cpp : Client certificate Authenticated");


	if(EN_DHPARAMS){
		//DH
		DH *dh;
		BIO *bio;
		bio = BIO_new_file(DHPARAMS, "r");
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


	if(EN_ECPARAMS){
		/*ECDH*/
		EC_KEY *ecdh = NULL;
		EC_GROUP *ecg = NULL;
		BIO *bio;
		bio = BIO_new_file(ECPARAMS, "r");


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

	struct timespec start, end;
	/*Establish a TCP connection*/
	/*listening socket*/
	bio = BIO_new_accept((this->portNumber).c_str());

	if(!bio)
		int_error("SocketServer.cpp : Error setting accept");
	//BIO_set_nbio(bio, 200);
	if(BIO_do_accept(bio) <= 0)
		int_error("SicketServer.cpp : Error binding the server Socket");

	for(;;){
/*#if HANDSHAKES_CNT_LOOP
		int loopCnt = HANDSHAKES_CNT + 1;
		bool firstConn = TRUE;
		uint64_t fTime = 0, rTime = 0; double fCpu = 0, rCpu = 0;
		while(loopCnt--){

#endif
*/
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
		
		/*SocketServer.cpp : Time Measurement for SSL connection*/
		//struct rusage stCpu;
		//struct rusage eCpu;

		struct timespec stCpu, eCpu;

		/*if(getrusage(RUSAGE_SELF, &stCpu) == -1){
			perror("SocketServer.cpp : StartCPU Usage not fetched");
		}*/
		clock_gettime(CLOCK_THREAD_CPUTIME_ID, &stCpu);
		clock_gettime(CLOCK_MONOTONIC_RAW, &start);

		//uint64_t tempTimeSt = start.tv_nsec / 1000;
		//time("SocketServer.cpp : Handshake Start time : ", tempTimeSt);
		if(SSL_accept(this->conn) != 1){
			fail("SocketServer.cpp : SSL accept Fail"); perror("");
			ERR_print_errors_fp(stderr);
			SSL_clear(conn);
			exit(1);
		}else{
			pass("SocketServer.cpp : SSL accept is successful");
		}

		clock_gettime(CLOCK_MONOTONIC_RAW, &end);
		clock_gettime(CLOCK_THREAD_CPUTIME_ID, &eCpu);
		/*if(getrusage(RUSAGE_SELF, &eCpu) == -1){
			perror("SocketServer.cpp : EndCPU Usage not fetched");
		}*/
		//uint64_t tempTimeEnd = end.tv_nsec / 1000;
		//time("SocketServer.cpp : Handshake End time : ", tempTimeEnd);

		uint64_t delta_us = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_nsec - start.tv_nsec) / 1000;
		time("SocketServer.cpp : Handshake time : ", delta_us);
		/*uint64_t delta_cpu_user_us = (eCpu.ru_utime.tv_sec - stCpu.ru_utime.tv_sec) * 1000000 + (eCpu.ru_utime.tv_usec - stCpu.ru_utime.tv_usec);
		cpu("SocketServer.cpp : User CPU time : ", delta_cpu_user_us);
		uint64_t delta_cpu_sys_us = (eCpu.ru_stime.tv_sec - stCpu.ru_stime.tv_sec) * 1000000 + (eCpu.ru_stime.tv_usec - stCpu.ru_stime.tv_usec);
		cpu("SocketServer.cpp : System CPU time : ", delta_cpu_sys_us);
		*/
		/*Generally user CPU time is more than system CPU time*/
		uint64_t delta_cpu_us = (eCpu.tv_sec - stCpu.tv_sec) * 1000000 + (eCpu.tv_nsec - stCpu.tv_nsec) / 1000;
		cpu("SocketServer.cpp : CPU time : ", delta_cpu_us);


		/*The selected Cipher-suite by the server is */
		if(DEBUG)
		cipher("SocketServer.cpp :  Server selected Cipher : ", SSL_get_cipher(conn));

		SSL_shutdown(this->conn);
		BIO_free(this->bioClient);
		this->conn = NULL;
		this->bioClient = NULL;



#if HANDSHAKES_CNT_LOOP
		//serverOpFile << delta_us << "," << delta_cpu_user_us  << "," << delta_cpu_sys_us << "," << delta_cpu_user_us + delta_cpu_sys_us << "\n";
		serverOpFile << delta_us << "," << delta_cpu_us << "\n";
#endif
/*
		if(firstConn){
				fTime = delta_us;
				fCpu = delta_cpu_user_us + delta_cpu_sys_us;
				firstConn = FALSE;
			}else{
				rTime += delta_us;
				rCpu += delta_cpu_user_us + delta_cpu_sys_us;
			}
		}

		fprintf(stderr, "Server On 1st  Connection : [%s]  %llu us\t [%s]  %f us\n", CLOCK, fTime, CPU_USE, fCpu);
		fprintf(stderr, "Server On Sess Resumption : [%s]  %llu us\t [%s]  %f us\n", CLOCK, rTime/HANDSHAKES_CNT, CPU_USE, rCpu/HANDSHAKES_CNT);

#endif
*/

		/*Leave one line*/
		cout << endl;
	}

	return 0;
}

int SocketServer::send(std::string message){
	const char* writeBuffer = message.data();
	int length = message.length();
	int n = SSL_write(this->conn, writeBuffer, length);
	if(n < 0){
		perror("SocketServer.cpp : Error on writing to client");
		return 1;
	}else{
		cout << "Written successfully by the server" << endl;
	}
	return 0;
}

string SocketServer::receive(int size=1024){
	char readBuffer[size];
	int n = SSL_read(this->conn, readBuffer, sizeof(readBuffer));
	if(n < 0){
		perror("SocketServer.cpp : error on reading on the server");
	}
	return string(readBuffer);
}

SocketServer :: ~SocketServer(){

	BIO_free(this->bio);
	if(this->conn){
		int sd = SSL_get_fd(conn);
		close(sd);
	}
#if HANDSHAKES_CNT_LOOP
	if(this->serverOpFile.is_open())
	this->serverOpFile.close();
#endif
	SSL_CTX_free(ssl_ctx);	
	fprintf(stderr,"\n\033[1;35mServer Shutdown...\033[0m\n");
}
