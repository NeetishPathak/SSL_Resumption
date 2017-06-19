/*client.cpp*/
#include <iostream>
#include <vector>
#include <utility>
#define CLOCK "\033[1;32m⏰ \033[0m"
#define CPU_USE "\033[1;34mCPU\033[0m"

#include "./network/SocketClient.h"
using namespace std;

int main(int argc, char **argv){
	if(argc < 2){
		perror("client.cpp : Incorrect usage:  ./client <IP of server> OR ./client <IP of server> <PortNumber> ");
		return 1;
	}
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
		cout << "Connect to Server Again (1/0)" << endl;
		cin >> connectAgain;
		if(TRUE == connectAgain){
			client.sslTcpConnect();
			client.sslTcpClosure();
		}else if(FALSE == connectAgain){
			cout << "Exiting Client " << endl;
			break;
		}else{
			cout << "Invalid Selection " << endl;
			break;
		}
	}
#else
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

#endif

	if(client.isServerConnected()){
		client.disconnectFromServer();
	}
	return 0;
	
}
