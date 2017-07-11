/********************************************************************
 * Filename : common.cpp
 * Author: Neetish Pathak (nepathak@paypal.com)
 * Description: 1) contains commonly used (by server and client) data & functions
 *				2) Callback functions for session info update and use
 ********************************************************************/
#include "common.h"

/*Test Case Names*/
const char* testCaseNames[] = {"NONE", "TLS1_2_NO_RESUMPTION", "TLS1_2_SESSION_IDS", "TLS1_2_SESSION_TICKETS", "TLS1_3_NO_RESUMPTION",\
								"TLS1_3_PSK", "TLS1_3_EXT_PSK_BDATA" ,"TLS1_3_EXT_SESSION", "TLS1_3_0_RTT","TLS1_2_FALSE_START"};

/*PSK related datatypes*/
char *psk_key = PSK_BDATA;    /* by default PSK is not used */
const unsigned char tls13_aes128gcmsha256_id[] = { 0x13, 0x01 };
const unsigned char tls13_aes256gcmsha384_id[] = { 0x13, 0x02 };

/*TLS variables*/
test_Case_Num testCaseNo = NONE;
cipher_t cipherType = NONE_CIPHER;
bool sessResume = false;
bool noSessionTickets = true;
bool tlsV1_3 = false;
bool pskTlsV1_3 = false;
char *sess_file = SESS_OUT;
int minTlsVersion = TLS1_VERSION;
int maxTlsVersion = TLS1_2_VERSION;
std::string clientLogName = "";
std::string serverLogName = "";
std::ofstream clientOpFile;
std::ofstream serverOpFile;

/**************************************************
 *Function: initTLS
 *Parameters: test_Case_Num tc
 *Return type: void
 *Description: Load TLS Configurations
 *			   tc: test_case code , configuration
 *			   	   is loaded for specific test case
 * ************************************************/
void initTLS(test_Case_Num tc){

	/*Initialize TLS variables for the test case*/
	testCaseNo = (test_Case_Num)tc;
	switch(testCaseNo){

		case TLS1_2_NO_RESUMPTION:
			sessResume = false;
			noSessionTickets = true;
			tlsV1_3 = false;
			pskTlsV1_3 = false;
			break;

		case TLS1_2_SESSION_IDS:
			sessResume = true;
			noSessionTickets = true;
			tlsV1_3 = false;
			pskTlsV1_3 = false;
			break;

		case TLS1_2_SESSION_TICKETS:
			sessResume = true;
			noSessionTickets = false;
			tlsV1_3 = false;
			pskTlsV1_3 = false;
			break;

		case TLS1_3_NO_RESUMPTION:
			sessResume = false;
			noSessionTickets = true;
			tlsV1_3 = true;
			pskTlsV1_3 = false;
			maxTlsVersion = TLS1_3_VERSION;
			break;

		case TLS1_3_SHARED_PSK_SESSION:
			sessResume = true;
			noSessionTickets = true;
			tlsV1_3 = true;
			pskTlsV1_3 = false;
			maxTlsVersion = TLS1_3_VERSION;
			break;

		case TLS1_3_EXT_PSK_BDATA:
			sessResume = false;
			noSessionTickets = true;
			tlsV1_3 = true;
			pskTlsV1_3 = true;
			sess_file = NULL;
			maxTlsVersion = TLS1_3_VERSION;
			break;

		case TLS1_3_EXT_PSK_SESSION:
			sessResume = false;
			noSessionTickets = true;
			tlsV1_3 = true;
			pskTlsV1_3 = true;
			maxTlsVersion = TLS1_3_VERSION;
			break;

		case TLS1_3_0_RTT:
		case TLS1_2_FALSE_START:
		default:
			fail("Invalid Test Case");
			exit(-1);
			break;
	}



}

/********************************************************
 *Function: setClientLogFilename, setServerLogFilename
 *Parameters: test_Case_Num tc, cipher_t
 *Return type: std::string
 *Description: set the log file names based on testcase
 *				and ciphertype
 * ****************************************************/

std::string setClientLogFileName(test_Case_Num tc, cipher_t c){
		/*initialize log file name for client*/
		clientLogName = tostring(CLIENT_LOG_DIR) + tostring(tc) + "_" + tostring(c) + "_TS_Client.csv";
		return clientLogName;
}
std::string setServerLogFileName(test_Case_Num tc, cipher_t c){
		/*initialize log file name for server*/
		serverLogName = tostring(SERVER_LOG_DIR) + tostring(tc) + "_" + tostring(c) + "_TS_Server.csv";
		return serverLogName;
}


/*SSL/TLS - Utility functions*/
/************************************************************
 *Function: handle_error
 *Parameters: const char *file, int lineno, const char	*msg
 *Return type: void
 *Description: error handling logs on stderr output
 *			   const char* file: fileName
 *			   int lineno: line number for the error
 *			   const char* msg : message for the error
 * *********************************************************/
void handle_error(const char *file, int lineno, const char	*msg){
	fprintf(stderr, " ** %s %i %s \n", file, lineno, msg);
	ERR_print_errors_fp(stderr);
	exit(-1);
}

/************************************************************
 *Function: init_OpenSSL
 *Parameters: NA
 *Return type: void
 *Description: Initialize the OpenSSL library functions
 * *********************************************************/
void init_OpenSSL(){
	if(!SSL_library_init()){
		fail("OpenSSL Initialization Failed");
		exit(-1);
	}
	SSL_load_error_strings();
}

/*Fancy print functions*/
/**********************************************************************
 *Function: warn, pass, fail, time, cpu, cipher, cipherAll, runTestCase
 *Parameters: const char* str
 *Return type: void
 *Description: print the logs with fancy icons
 * *******************************************************************/
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

/**************************************************************
 * Function: debug
 * Parameters: const char* val
 * Return Type: void
 * Description: to enable debug logs
 * ***********************************************************/
void debug(const char* val){
#if DEBUG
	perror(val);
#endif
}

/**************************************************************
 * Function: toString
 * Parameters: const T& t (template implementation)
 * Return Type: std::string
 * Description: to convert T type to string
 * ***********************************************************/
template <typename T>
std::string tostring(const T& t)
{
    std::ostringstream ss;
    ss << t;
    return ss.str();
}
