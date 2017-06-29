#include "common.h"

/*TLS1_2 Ciphers*/
std::string TLS1_2_CIPHERS[NUM_TLS1_2_TESTED_CIPHERS] = {ECDSA256_ECDHE256, RSA2048_ECDHE256, RSA2048_DHE2048, \
													RSA2048_DHE1024, RSA3072, RSA2048};

/*TLS1_3 Ciphers*/
std::string TLS1_3_CIPHERS[NUM_TLS1_3_TESTED_CIPHERS] = {TLS1_3_AES256, TLS1_3_AES128, TLS1_3_CHACHA20};

/*Test Parameters*/
bool Tls1_2_NoResumption = false;
bool Tls1_2_SessionIds = false;
bool Tls1_2_SessionTickets = false;
bool Tls1_2_FalseStart = false;
bool Tls1_3_NoResumption = false;
bool Tls1_3_PSK = false;
bool Tls1_3_Zero_RTT = false;
bool Tls1_3_preGenPSK = false;

void handle_error(const char *file, int lineno, const char	*msg){
	fprintf(stderr, " ** %s %i %s \n", file, lineno, msg);
	ERR_print_errors_fp(stderr);
	exit(-1);
}

void init_OpenSSL(){
	if(!SSL_library_init()){
		fail("OpenSSL Initialization Failed");
		exit(-1);
	}
	SSL_load_error_strings();
}

void warn(const char* warnStr){
	if(DEBUG)
	fprintf(stderr, "[%s] %s\n", WARN, warnStr);
}

void pass(const char* passStr){
	if(DEBUG)
	fprintf(stderr, "[%s] %s\n", CHECK, passStr);
}

void fail(const char* Str){
	if(DEBUG)
	fprintf(stderr, "[%s] %s\n", BALLOT, Str);
}

void time(const char * timeStr, uint64_t delta_time){
	if(DEBUG)
	fprintf(stderr, "[%s] %s %llu us\n", CLOCK, timeStr, delta_time);
}

void cpu(const char * cpuStr, double cpuTime){
	if(DEBUG)
	fprintf(stderr, "[%s] %s %f us\n", CPU_USE, cpuStr, cpuTime);
}

void cipher(const char * cpuStr, const char* cipher){
	if(DEBUG)
	fprintf(stderr, "[%s] %s %s \n", CIPHER, cpuStr, cipher);
}

void debug(const char* val){
#if DEBUG
	perror(val);
#endif
}

template <typename T>
std::string tostring(const T& t)
{
    std::ostringstream ss;
    ss << t;
    return ss.str();
}
