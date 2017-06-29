/*client.cpp*/
#include <iostream>
#include <vector>
#include <utility>
#include <fstream>

#define CLOCK "\033[1;32m⏰ \033[0m"
#define CPU_USE "\033[1;34mCPU\033[0m"

#include "./network/SocketClient.h"
using namespace std;
std::string getTabs(){
	std::string s = "";
	for(int i=1; i<CIPHERTYPE; ++i){
		s += ",";
	}
	return s;
}
unsigned int getTestCase(){
	unsigned int tCase = NONE;
	cout << "Enter the TLS connection Type: \n" \
			"TLS 1.2 No Resumption (1) \n" \
			"TLS 1.2 Resumption - Session Ids (2)\n" \
			"TLS 1.2 Resumption - Session Tickets (3)\n" \
			"TLS 1.2 False Start (4)\n" \
			"TLS 1.3 No Resumption (5)\n" \
			"TLS 1.3 Resumption PSK (6)\n" \
			"TLS 1.3 0-RTT (7)\n" \
			"TLS 1.3 Resumption Pre-Generated PSK (8)" << endl;
	cin >> tCase ;
	return tCase;
}

int main(int argc, char **argv){
	if(argc < 2){
		perror("client.cpp : Incorrect usage:  ./client <IP of server> OR ./client <IP of server> <PortNumber> ");
		return 1;
	}
	//unsigned testCase = getTestCase();

	SocketClient client(argv[1], argc==3?argv[2]:PORT);
	int connectAgain = FALSE;
	pair<uint64_t, double>  clientStats;
	client.connectToServer();

#if CLIENT_THREADS_ON
	initializeClientConnThreads();
	client.sslTcpClosure();
#else
	clientStats = client.sslTcpConnect();
	client.sslTcpClosure();
#endif

#if (HANDSHAKES_CNT_LOOP == 0)
	while(1){
		cout << "\nConnect to Server Again (1/0)" << endl;
		cin >> connectAgain;
		if(TRUE == connectAgain){
			client.sslTcpConnect();
			client.sslTcpClosure();
		}else if(FALSE == connectAgain){
			cout << "\033[1;36mExiting Client\033[0m " << endl;
			break;
		}else{
			cout << "Invalid Selection " << endl;
			break;
		}
	}
#else
	std::ofstream testReportFile;
	testReportFile.open("testCase1.csv",std::ofstream::out);
	testReportFile << "ECDSA256_ECDHE256, RSA2048_ECDHE256, RSA2048_DHE2048, RSA2048_DHE1024, RSA3072, RSA2048\n";
	int loopCnt = HANDSHAKES_CNT;
	pair<uint64_t, double> clientLoopStats;
	connectAgain = TRUE;
	while(loopCnt--){
		pair<uint64_t, double> clientLoopLocalStats;
		if(TRUE == connectAgain){
			clientLoopLocalStats = client.sslTcpConnect();
			client.sslTcpClosure();
			clientLoopStats.first += clientLoopLocalStats.first;
			clientLoopStats.second += clientLoopLocalStats.second;
			testReportFile << getTabs() << clientLoopLocalStats.first << "\n";
		}else if(FALSE == connectAgain){
			cout << "Exiting Client " << endl;
			break;
		}else{
			cout << "Invalid Selection " << endl;
			break;
		}
	}
	clientLoopStats.first /= HANDSHAKES_CNT;
	clientLoopStats.second /= HANDSHAKES_CNT;
	fprintf(stderr, "Client On 1st  Connection : [%s]  %llu us\t [%s]  %f us\n", CLOCK, clientStats.first, CPU_USE, clientStats.second);
	fprintf(stderr, "Client On Sess Resumption : [%s]  %llu us\t [%s]  %f us\n", CLOCK, clientLoopStats.first, CPU_USE, clientLoopStats.second);
	testReportFile.close();
#endif

	if(client.isServerConnected()){
		client.disconnectFromServer();
	}
	return 0;
	
}
