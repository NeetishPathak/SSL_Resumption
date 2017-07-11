/********************************************************************
 * Filename : client.cpp
 * Author: Neetish Pathak (nepathak@paypal.com)
 * Description: 1) Contains the main method for the client program
 ********************************************************************/
/*client.cpp*/
#include <iostream>
#include "./network/SocketClient.h"
using namespace std;

/*********************************************************************
 * Function: main
 * Parameters: int argc, char** argv
 * Return value: int
 * Description: main program for client
 * 				argc: no. of input arguments
 * 				argv: input arguments
 * *******************************************************************/
int main(int argc, char **argv){
	/*Check input parameters*/
	if(argc < 4 || argc > 5){
		perror("client.cpp : Incorrect usage:  ./client <IP of server> <testCase> <ciphertype> OR ./client <IP of server> <testCase> <cipherType> <PortNumber>");
		return 1;
	}

	/*Read the test Case and the cipher type*/
	test_Case_Num tc = (test_Case_Num)(atoi(argv[2]));
	cipher_t c = (cipher_t)(atoi(argv[3]));

	/*Open the client Log file*/
	clientOpFile.open(setClientLogFileName(tc,c).c_str(),std::ofstream::out);

/*Make program for extensible for multi threads*/
#if CLIENT_THREADS_ON
	initializeClientConnThreads();
	client.sslTcpClosure();
#endif

#if (HANDSHAKES_CNT_LOOP == TRUE)
	int loopCnt = HANDSHAKES_CNT;
	while(loopCnt--){
		cout << "LoopCount " << HANDSHAKES_CNT-loopCnt << endl;
		/*Make a client object*/
		SocketClient client(argv[1], argc==5?argv[4]:PORT, tc, c);
		/*Connect the client to the server*/
		client.connectToServer();
		/*Close TCP/SSL connection*/
		client.sslTcpClosure();
		/*Disconnect with the server*/
		if(client.isServerConnected()){
			client.disconnectFromServer();
		}
	}
#endif

	/*close the client Log file*/
	if(clientOpFile.is_open())
	clientOpFile.close();

	return 0;
}
