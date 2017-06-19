/*server.cpp*/

#include "network/SocketServer.h"

using namespace std;

int main(int argc, char **argv){

	SocketServer server(argc==2?argv[1]:PORT);
	server.listen();
}
