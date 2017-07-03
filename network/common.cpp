#include "common.h"

const char* testCaseNames[] = {"NONE", "TLS1_2_NO_RESUMPTION", "TLS1_2_SESSION_IDS", "TLS1_2_SESSION_TICKETS", "TLS1_3_NO_RESUMPTION" \
								"TLS1_3_PSK", "TLS1_3_PRE_PSK", "TLS1_3_0_RTT" "TLS1_2_FALSE_START"};


char *psk_key = "0533c95c9ecc310ee07cb70a316c45448487c1f70bbea99fe6616f3348305677";           /* by default PSK is not used */
const unsigned char tls13_aes128gcmsha256_id[] = { 0x13, 0x01 };
const unsigned char tls13_aes256gcmsha384_id[] = { 0x13, 0x02 };


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
	fprintf(stderr, "[%s] %s %lu us\n", CLOCK, timeStr, delta_time);
}

void cpu(const char * cpuStr, uint64_t cpuTime){
	if(DEBUG)
	fprintf(stderr, "[%s] %s %lu us\n", CPU_USE, cpuStr, cpuTime);
}

void cipher(const char * cpuStr, const char* cipher){
	if(DEBUG)
	fprintf(stderr, "[%s] %s %s \n", CIPHER, cpuStr, cipher);
}

void cipherAll(const char * cpuStr, const char* cipher){
	if(DEBUG)
	fprintf(stderr, "[%s] %s %s \n", CIPHERALL, cpuStr, cipher);
}

void runTestCase(const char * cpuStr, const char* cipher){
	if(DEBUG)
	fprintf(stderr, "[%s] %s %s \n", RUNTEST, cpuStr, cipher);
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
