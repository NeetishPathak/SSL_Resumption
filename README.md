# SSL_Resumption

## Pre-requisites
Openssl library version OpenSSL 1.1.1-dev <br />
To install the latest OpenSSL master branch, follow the following steps: <br />
$ git clone https://github.com/openssl/openssl.git <br />
$ cd openssl <br />
$ ./config --prefix=/usr/local <br />
(–prefix is used to mention the top of the installation directory tree. Default directory is /usr/local for unix system) <br />
$ ./config enable-tls1_3 <br />
(do step 4 only if tls1.3 is to be enabled) <br />
$ make -j2 <br />
$ sudo make install <br />
$ openssl help <br />

## Build Instructions
1) build.sh file is the main build file. The command to build the server client pair is <br />
	sh build.sh <br />
	e.g $ sh build.sh <br />
	

## Run Instructions
1) Command to run the server program <br />
	./server <test_case_code> <ciphertype> [port No (Optional param - default port is 12345)] <br />
2) Command to run the client program <br />
	./client <server_ip> <test_case_code> <ciphertype> [port No (Optional param - default port is 12345)] <br />

3) The client server pair can be run to test different testCases with various ciphersuites. Following Testcases Codes are supported. <br />
### TestCase_Code	&ensp;&ensp;	Test case Explanation
	1		TLS1.2_No Session Resumption Connection
	2		TLS1.2_Session Resumption using Session Identifiers
	3		TLS1.2_Session Resumption using Session Tickets
	4		TLS1.3_No Session Resumption Connection
	5		TLS1.3_Session Resumption using Shared PSK
	6		TLS1.3_Session Resumption using External PSK 
	7 		TLS1.3_Session Resumption using External Session file
	8		TLS1.3_Session Resumption with Early Data
							
### Ciphersuite_Code	&ensp;&ensp;	CipherSuite Explanation
	1		ECDHE-ECDSA-AES256-GCM-SHA384 with X25519 Elliptic curve
	11		ECDHE-ECDSA-AES256-GCM-SHA384 with prime256v1 EC Param, 2048 bits DH Param
	2		ECDHE-RSA-AES256-GCM-SHA384 with X25519 Elliptic curve, 2048 bits RSA keys
	21		ECDHE-RSA-AES256-GCM-SHA384 with prime256v1 EC Param, 2048 bits DH Param, 2048 bits RSA keys
	3		DHE-RSA-AES256-GCM-SHA384 with 2048 bits DH Param
	4		DHE-RSA-AES256-GCM-SHA384 with 1024 bits DH Param
	5		AES256-GCM-SHA384 with 3072 bits RSA keys
	6		AES256-GCM-SHA384 with 2048 bits RSA keys
	7		TLS13-AES-128-GCM-SHA256 with X25519 Elliptic Curve
	71		TLS13-AES-128-GCM-SHA256 with prime256v1 EC Param, 2048 bits DH Param
	8		TLS13-AES-128-GCM-SHA256 with X25519 Elliptic curve, 2048 bits RSA keys
	81		TLS13-AES-128-GCM-SHA256 with prime256v1 EC Param, 2048 bits DH Param, 2048 bits RSA keys

#### Note: 
CipherSuite_Code 1, 11, 2, 21, 3, 4, 5, 6 can be only used with TLS 1.2 (TestCase_Code 1,2 and 3) <br />
CipherSuite_Code 7, 71, 8, 81 can be only used with TLS 1.3 (TestCase_Code 4,5, 6,7) <br />
Only CipherSuite_Code 7 and 8 should be used with early Data test Case i.e. test Case 8

4) Example run <br />

a) ./server 1 1 <br/>
run server for no session resumption connection on TLS 1.2 using cipher suite ECDHE-ECDSA-AES256-GCM-SHA384 using elliptic curve X25519 <br />
./client 10.176.3.159 1 1 <br/>
run client to connect to server running on 10.176.3.159 for the no resumption connection on TLS 1.2 using cipher suite ECDHE-ECDSA-AES256-GCM-SHA384 using elliptic curve X25519 <br />

b) ./server 4 7	6001 <br/>
run server acceptinfg connection on port 6001 for no session resumption connection on TLS 1.3 using cipher suite TLS13-AES-128-GCM-SHA256 using elliptic curve X25519 <br />
./client 10.176.3.159 4 7 6001 <br/>
run client to connect to server running on 10.176.3.159 on port 6001 for no session resumption connection on TLS 1.3 using cipher suite TLS13-AES-128-GCM-SHA256 using elliptic curve X25519 <br />
	
## Keys, Certificates, Session Files
1) All the private keys and certificates can be found under ./network/credentials/keys directory <br />
2) Session file in ./network/credentials/sessionFiles is written when Session Resumption is on <br />




