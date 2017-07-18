/********************************************************************
 * Filename : common.h
 * Author: Neetish Pathak (nepathak@paypal.com)
 * Description: Header file for the common data and utility functions
 ********************************************************************/
/*common.h*/
#ifndef COMMON_H_
#define COMMON_H_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <iostream>
#include <sstream>
#include <string>
#include <utility>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <fstream>
#include <openssl/e_os2.h>
#include <openssl/bn.h>

#include <openssl/opensslconf.h>

#include <openssl/crypto.h>

#include <openssl/ocsp.h>

/*To string Macro*/
#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)
#define NUM_TO_STR(x) STR(x)

/*Supporting Unix or WIndows Thread*/
#ifndef WIN32
#include <pthread.h>
#define THREAD_CC
#define THREAD_TYPE	pthread_t
#define THREAD_CREATE(tid, entry, arg)	pthread_crete(&tid, NULL, entry, arg)
#else
#include <windows.h>
#define THREAD_CC	_ _cdec1
#define THREAD_TYPE	DWORD
#define THREAD_CREATE(tid, entry, arg) do{ _beginthread(entry, 0, arg); \
											tid = GetCurrentThreadId();} while (0)
#endif

/*Status print Icons*/
#define BEGIN "\r\033[2K"
#define CHECK "\033[1;32m✔\033[0m"
#define BALLOT "\033[1;31m✘\033[0m"
#define WARN "\033[1;33m‼\033[0m"
#define CLOCK "\033[1;32m⏰ \033[0m"
#define CPU_USE "\033[1;34mCPU\033[0m"
#define CIPHER "\033[1;32m🔑 \033[0m"
#define CIPHERALL "\033[1;32m🗝 \033[0m"
#define RUNTEST "\033[1;32m⏩ \033[0m"

/*General Macros*/
#define TRUE 1
#define FALSE 0
#define DEBUG TRUE

/*TimeStamping functions*/
#define GET_TIME(x) clock_gettime(CLOCK_MONOTONIC_RAW, &x)
#define GET_CPU(x) clock_gettime(CLOCK_THREAD_CPUTIME_ID, &x)
//To get both system and user level CPU utilization
#define GET_CPU2(x) getrusage(RUSAGE_SELF, &x)

/*Connection Macros*/
#define PORT "12345"
#define CIPHERSUITE_ALL "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA:RSA-PSK-AES256-GCM-SHA384:DHE-PSK-AES256-GCM-SHA384:RSA-PSK-CHACHA20-POLY1305:DHE-PSK-CHACHA20-POLY1305:ECDHE-PSK-CHACHA20-POLY1305:AES256-GCM-SHA384:PSK-AES256-GCM-SHA384:PSK-CHACHA20-POLY1305:RSA-PSK-AES128-GCM-SHA256:DHE-PSK-AES128-GCM-SHA256:AES128-GCM-SHA256:PSK-AES128-GCM-SHA256:TLS13-AES-256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256:AES256-SHA256:AES128-SHA256:ECDHE-PSK-AES256-CBC-SHA384:ECDHE-PSK-AES256-CBC-SHA:SRP-RSA-AES-256-CBC-SHA:SRP-AES-256-CBC-SHA:RSA-PSK-AES256-CBC-SHA384:DHE-PSK-AES256-CBC-SHA384:RSA-PSK-AES256-CBC-SHA:DHE-PSK-AES256-CBC-SHA:AES256-SHA:PSK-AES256-CBC-SHA384:PSK-AES256-CBC-SHA:ECDHE-PSK-AES128-CBC-SHA256:ECDHE-PSK-AES128-CBC-SHA:SRP-RSA-AES-128-CBC-SHA:SRP-AES-128-CBC-SHA:RSA-PSK-AES128-CBC-SHA256:DHE-PSK-AES128-CBC-SHA256:RSA-PSK-AES128-CBC-SHA:DHE-PSK-AES128-CBC-SHA:AES128-SHA:PSK-AES128-CBC-SHA256:PSK-AES128-CBC-SHA"

/*Session File*/
#define SESS_OUT "./network/credentials/sessionFiles/sess_client.pem"
#define SESS_PSK_EXT "./network/credentials/sessionFiles/sess_psk_ext.pem"

/*Shared PSK Binary Data*/
#define PSK_BDATA "0533c95c9ecc310ee07cb70a316c45448487c1f70bbea99fe6616f3348305677"

/*Early Data*/
#define EARLY_DATA TRUE
#define READ_WRITE_TEST TRUE
//#define WRITE_DATA "GET / HTTP/1.1\r\nHost: \r\nConnection: close\r\n\r\n"
#define WRITE_DATA "Message \0"

/*TestCase Run Count*/
#define HANDSHAKES_CNT 20
#define HANDSHAKES_CNT_LOOP TRUE

/*Log files*/
#define CLIENT_LOG_DIR "./Statistics/ClientLogs/"
#define SERVER_LOG_DIR "./Statistics/ServerLogs/"

/*Test Ciphers*/
#define ECDSA256_ECDHE256 "ECDHE-ECDSA-AES128-SHA256"
#define RSA2048_ECDHE256 "ECDHE-RSA-AES128-SHA256"
#define RSA2048_DHE2048 "DHE-RSA-AES128-SHA256"
#define RSA2048_DHE1024 "DHE-RSA-AES128-SHA256"
#define RSA3072 "AES128-SHA256"
#define RSA2048 "AES128-SHA256"
#define TLS1_3_AES256 "TLS13-AES-128-GCM-SHA256"
#define TLS1_3_CHACHA20 "TLS13-CHACHA20-POLY1305-SHA256"
#define TLS1_3_AES128 "TLS13-AES-128-GCM-SHA256"

/*Cipher type*/
typedef enum _CIPHERS{
	NONE_CIPHER = 0,
	ECDHE_ECDSA256_X25519 = 1,
	ECDHE256_ECDSA256 = 11,
	ECDHE_RSA2048_X25519 = 2,
	ECDHE256_RSA2048 = 21,
	DHE2048_RSA2048 = 3,
	DHE1024_RSA2048 = 4,
	RSA_3072 = 5,
	RSA_2048 = 6,
	TLS1_3_ECDHE_ECDSA256_X25519 = 7,
	TLS1_3_ECDHE256_ECDSA256 = 71,
	TLS1_3_ECDHE_RSA2048_X25519 = 8,
	TLS1_3_ECDHE256_RSA2048 = 81
} cipher_t;

/*Test Case params*/
typedef enum _TEST_CASE_ENUMS{
	NONE,
	TLS1_2_NO_RESUMPTION,
	TLS1_2_SESSION_IDS,
	TLS1_2_SESSION_TICKETS,
	TLS1_3_NO_RESUMPTION,
	TLS1_3_SHARED_PSK_SESSION,
	TLS1_3_EXT_PSK_BDATA,
	TLS1_3_EXT_PSK_SESSION,
	TLS1_3_0_RTT,
	TLS1_2_FALSE_START
} test_Case_Num;

/*externed values*/
extern const char* testCaseNames[];
extern char *psk_key;           /* by default PSK is not used */
extern const unsigned char tls13_aes128gcmsha256_id[];
extern const unsigned char tls13_aes256gcmsha384_id[];
extern test_Case_Num testCaseNo;
extern bool sessResume;
extern bool noSessionTickets;
extern bool tlsV1_3;
extern bool pskTlsV1_3;
extern char *sess_file;
extern int minTlsVersion;
extern int maxTlsVersion;
extern std::string clientLogName;
extern std::string serverLogName;
extern std::ofstream clientOpFile;
extern std::ofstream serverOpFile;


/*Common functions*/
#define int_error(msg) handle_error(__FILE__, __LINE__, msg)
void handle_error(const char *file, int lineno, const char	*msg);
void init_OpenSSL();
void initTLS(test_Case_Num tc);
std::string setClientLogFileName(test_Case_Num tc, cipher_t c);
std::string setServerLogFileName(test_Case_Num tc, cipher_t c);

/* Display functions */
void warn(const char *);
void pass(const char *);
void fail(const char*);
void time(const char*, uint64_t);
void cpu(const char*,  uint64_t);
void cipher(const char*, const char* );
void cipherAll(const char * cpuStr, const char* cipher);
void runTestCase(const char*, const char*);
uint64_t timeDiff(const char * timeStr, struct timespec startTime, struct timespec endTime);
uint64_t cpuDiff(const char * cpuStr, struct timespec startTime, struct timespec endTime);
uint64_t cpuDiffSysUser(const char * cpuStr, struct rusage startCpuTime, struct rusage endCpuTime, uint64_t &cU, uint64_t &cS);
template <typename T>
std::string tostring(const T& t);

#endif


