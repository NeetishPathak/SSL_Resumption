/*server.cpp*/

#include "network/SocketServer.h"
using namespace std;

int main(int argc, char **argv){
	runTestCase("Server - Running test Case", testCaseNames[TESTCASE]);
	SocketServer server(argc==2?argv[1]:PORT);
	server.listen();
	return 0;
}
