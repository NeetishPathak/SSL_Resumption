/********************************************************************
 * Filename : SocketClient.cpp
 * Author: Neetish Pathak (nepathak@paypal.com)
 * Description: 1) contains main function for server program.
 ********************************************************************/
/*server.cpp*/

#include "network/SocketServer.h"
using namespace std;

/*********************************************************************
 * Function: main
 * Parameters: int argc, char** argv
 * Return type: int
 * Description: main program for server
 * 				argc: no. of input arguments
 * 				argv: input arguments
 * *******************************************************************/
int main(int argc, char **argv){
	/*Check the input parameters*/
	if(argc < 3 || argc > 4){
		perror("server.cpp : Incorrect usage:  ./server <testCase> <ciphertype> OR ./client <testCase> <cipherType> <PortNumber>");
		return 1;
	}

	/*Read the testcase and cipher type*/
	test_Case_Num tc = (test_Case_Num)(atoi(argv[1]));
	cipher_t c = (cipher_t)(atoi(argv[2]));

	/*Open serverLog file*/
	serverOpFile.open(setServerLogFileName(tc,c).c_str(),std::ofstream::out);

	/*Initialize the server program*/
	SocketServer server(argc==4?argv[3]:PORT,tc,c);
	server.listen();

	/*Close the server log file*/
	if(serverOpFile.is_open())
		serverOpFile.close();

	return 0;
}
