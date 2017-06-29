/*common.h*/
#ifndef COMMON_H_
#define COMMON_H_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
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

/*General Macros*/
#define TRUE 1
#define FALSE 0
#define DEBUG TRUE

/*Connection Macros*/
#define PORT "12345"
#define CIPHERSUITE_ALL "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA:RSA-PSK-AES256-GCM-SHA384:DHE-PSK-AES256-GCM-SHA384:RSA-PSK-CHACHA20-POLY1305:DHE-PSK-CHACHA20-POLY1305:ECDHE-PSK-CHACHA20-POLY1305:AES256-GCM-SHA384:PSK-AES256-GCM-SHA384:PSK-CHACHA20-POLY1305:RSA-PSK-AES128-GCM-SHA256:DHE-PSK-AES128-GCM-SHA256:AES128-GCM-SHA256:PSK-AES128-GCM-SHA256:TLS13-AES-256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256:AES256-SHA256:AES128-SHA256:ECDHE-PSK-AES256-CBC-SHA384:ECDHE-PSK-AES256-CBC-SHA:SRP-RSA-AES-256-CBC-SHA:SRP-AES-256-CBC-SHA:RSA-PSK-AES256-CBC-SHA384:DHE-PSK-AES256-CBC-SHA384:RSA-PSK-AES256-CBC-SHA:DHE-PSK-AES256-CBC-SHA:AES256-SHA:PSK-AES256-CBC-SHA384:PSK-AES256-CBC-SHA:ECDHE-PSK-AES128-CBC-SHA256:ECDHE-PSK-AES128-CBC-SHA:SRP-RSA-AES-128-CBC-SHA:SRP-AES-128-CBC-SHA:RSA-PSK-AES128-CBC-SHA256:DHE-PSK-AES128-CBC-SHA256:RSA-PSK-AES128-CBC-SHA:DHE-PSK-AES128-CBC-SHA:AES128-SHA:PSK-AES128-CBC-SHA256:PSK-AES128-CBC-SHA"

/*Main TestCase Config*/
#define SESS_RESUME FALSE
#define TLSv1_3 FALSE
#define NO_SESSION_TICKETS TRUE
#define CIPHERTYPE 1
#define FILE "1_1_TS_"
#define HANDSHAKES_CNT 999
#define HANDSHAKES_CNT_LOOP TRUE


#define CLIENT_FILENAME "./Statistics/ClientLogs/" FILE "Client.csv"
#define SERVER_FILENAME "./Statistics/ServerLogs/" FILE "Server.csv"
#define MIN_TLS_VERSION TLS1_VERSION
#define MAX_TLS_VERSION (TLSv1_3 == TRUE ? TLS1_3_VERSION : TLS1_2_VERSION)

/*Test Ciphers*/
#define ECDSA256_ECDHE256 "ECDHE-ECDSA-AES256-GCM-SHA384"
#define RSA2048_ECDHE256 "ECDHE-RSA-AES256-GCM-SHA384"
#define RSA2048_DHE2048 "DHE-RSA-AES256-GCM-SHA384"
#define RSA2048_DHE1024 "DHE-RSA-AES256-GCM-SHA384"
#define RSA3072 "AES256-GCM-SHA384"
#define RSA2048 "AES256-GCM-SHA384"
#define TLS1_3_AES256 "TLS13-AES-256-GCM-SHA384"
#define TLS1_3_CHACHA20 "TLS13-CHACHA20-POLY1305-SHA256"
#define TLS1_3_AES128 "TLS13-AES-128-GCM-SHA256"

/*Common functions*/
#define int_error(msg) handle_error(__FILE__, __LINE__, msg)
void handle_error(const char *file, int lineno, const char	*msg);
void init_OpenSSL();

/* Display functions */
void warn(const char *);
void pass(const char *);
void fail(const char*);
void time(const char*, uint64_t);
void cpu(const char*, double cpuUsage);
void cipher(const char*, const char* );
template <typename T>
std::string tostring(const T& t);

/*Test Case params*/
enum{
	NONE,
	TLS1_2_NO_RESUMPTION,
	TLS1_2_SESSION_IDS,
	TLS1_2_SESSION_TICKETS,
	TLS1_2_FALSE_START,
	TLS1_3_NO_RESUMPTION,
	TLS1_3_PSK,
	TLS1_3_0_RTT,
	TLS1_3_PRE_PSK
} TESTCASE;
#endif
