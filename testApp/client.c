#include "common.h"
 
#define CERTFILE "client.pem"
char *sess_in = NULL; char * sess_out = NULL;
BIO *bio_err = NULL;
static int new_session_cb(SSL *S, SSL_SESSION *sess)
{
    BIO *stmp = BIO_new_file(sess_out, "w");
    printf("new session callback is called \n");
    if (stmp == NULL) {
        BIO_printf(bio_err, "Error writing session file %s\n", sess_out);
    } else {
        PEM_write_bio_SSL_SESSION(stmp, sess);
        BIO_free(stmp);
    }

    /*
     * We always return a "fail" response so that the session gets freed again
     * because we haven't used the reference.
     */
    return 0;
}



SSL_CTX *setup_client_ctx(void)
{
    SSL_CTX *ctx;

    ctx = SSL_CTX_new(TLS_client_method( ));
    if (SSL_CTX_use_certificate_chain_file(ctx, CERTFILE) != 1)
        int_error("Error loading certificate from file");
    if (SSL_CTX_use_PrivateKey_file(ctx, CERTFILE, SSL_FILETYPE_PEM) != 1)
        int_error("Error loading private key from file");  
    return ctx;
}

int do_client_loop(SSL *ssl)
{
	int  err, nwritten, nread;
	        char buf[80]; char rbuf[80];
	        bzero(buf, sizeof(buf));
	        bzero(rbuf, sizeof(rbuf));

	        //for (;;)
	        {
	            if (!fgets(buf, sizeof(buf), stdin))
	                return 0;
	            /*for (nwritten = 0;  nwritten < sizeof(buf);  nwritten += err)
	            {
	                err = SSL_write(ssl, buf + nwritten, strlen(buf) - nwritten);
	                if (err <= 0){ printf("Returning\n");
	                    break;}else{
	                    	printf("No returning\n");
	                    }
	            }*/

	            err = SSL_write(ssl, buf, strlen(buf));
	            if(err <= 0)
	            	return 0;

	            /*for (nread = 0;  nread < sizeof(rbuf);  nread += err)
				{
					err = SSL_read(ssl, rbuf + nread, sizeof(rbuf) - nread);
					if (err <= 0)
						break;
				}*/

	            err = SSL_read(ssl, rbuf, sizeof(rbuf));
	            if (err <= 0)
	            	return 0;
				fwrite(buf, 1, sizeof(rbuf), stdout);
	        }
	        return 1;


    /*int  err, nread;
        char buf[80];

        do
        {
            for (nread = 0;  nread < sizeof(buf);  nread += err)
            {
                err = SSL_read(ssl, buf + nread, sizeof(buf) - nread);
                if (err <= 0)
                    break;
            }
            fwrite(buf, 1, nread, stdout);
        }
        while (err > 0);
        return 0;
       // return (SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN) ? 1 : 0; */
}
 
int main(int argc, char *argv[])
{
    BIO     *conn;
    SSL     *ssl;
    SSL_CTX *ctx;

    if(argc < 3){
    	fprintf(stderr,"Enter the name of inout and output file ./client <input_file> <output file>");
    	exit(1);

    }else{
    	sess_in = argv[1];
    	sess_out = argv[2];
    }


    init_OpenSSL(  );
    //seed_prng(  );

    ctx = setup_client_ctx(  );

    conn = BIO_new_connect(SERVER ":" PORT);
    if (!conn)
        int_error("Error creating connection BIO");

    bio_err = BIO_new_fp(stderr,
    		0x00 | (((1 | 0x8000) & 0x8000) == 0x8000 ? 0x10 : 0));

    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
        	SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);

/*
	 * In TLSv1.3 NewSessionTicket messages arrive after the handshake and can
	 * come at any time. Therefore we use a callback to write out the session
	 * when we know about it. This approach works for < TLSv1.3 as well.
	 */
	if (sess_out) {
		SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT
											| SSL_SESS_CACHE_NO_INTERNAL_STORE);
		SSL_CTX_sess_set_new_cb(ctx, new_session_cb);
		printf("client.c : new_session_cb is registered \n");
	}

    if (BIO_do_connect(conn) <= 0)
                int_error("Error connecting to remote machine");

    if (!(ssl = SSL_new(ctx)))
            int_error("Error creating an SSL context");

    sess_in = NULL;
	if (sess_in) {
		SSL_SESSION *sess;
		BIO *stmp = BIO_new_file(sess_in, "r");
		if (!stmp) {
			BIO_printf(bio_err, "Can't open session file %s\n", sess_in);
			ERR_print_errors(bio_err);
		}
		sess = PEM_read_bio_SSL_SESSION(stmp, NULL, 0, NULL);
		BIO_free(stmp);
		if (!sess) {
			BIO_printf(bio_err, "Can't open session file %s\n", sess_in);
			ERR_print_errors(bio_err);
		}
		if (!SSL_set_session(ssl, sess)) {
			BIO_printf(bio_err, "Can't set session\n");
			ERR_print_errors(bio_err);
		}
		SSL_SESSION_free(sess);
	}

 

    SSL_set_bio(ssl, conn, conn);
    if (SSL_connect(ssl) <= 0)
        int_error("Error connecting SSL object");

    fprintf(stderr, "SSL Connection opened\n");
    if (do_client_loop(ssl))
        SSL_shutdown(ssl);
    else
        SSL_clear(ssl);
    fprintf(stderr, "SSL Connection closed\n");

    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}


