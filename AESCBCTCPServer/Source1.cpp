/*#include <strings.h>

#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
using namespace std;

int main()  {
    int sockfd, newsockfd, portno;
    socklen_t clilen;
    char buffer[256];
    struct sockaddr_in serv_addr, cli_addr;
    int n;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd< 0)
    {
    	cerr<< "Error creating socket" <<endl;
        return 1;
    }
	// Clear address structure
	bzero((char *) &serv_addr, sizeof(serv_addr));
	portno = 5001;
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(portno);
    // Bind the socket to a specific address and port
    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
    {
    	cerr<< "Error binding socket" <<endl;
        return 1;
    }
    // Listen for incoming connections
    listen(sockfd,5);
    clilen = sizeof(cli_addr);
    // Accept an incoming connection
    newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
    if (newsockfd< 0)
    {
    	cerr<< "Error accepting connection" <<endl;
        return 1;
    }
    cout<< "Received message: " << buffer <<endl;
    // Write data to the client
    n = write(newsockfd,"I got your message",18);
    if (n < 0)
    {
    	cerr<< "Error writing to socket" <<endl;
        return 1;
    }
    close(newsockfd);
    close(sockfd);
    return 0;
}
*/

#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <iostream>
using namespace std;

#include <openssl/err.h>

#include <openssl/bio.h>
#include <openssl/bioerr.h>

#include <openssl/evp.h>
#include <openssl/evperr.h>

#include <sys/socket.h>
#include <unistd.h>
#define PORT 8080

enum enumErrors { FAILUER, SUCCESS, DECRYPTIONERROR, AUTHERROR };

bool DecryptCipher(unsigned char *byCipher, int nCipherLen, unsigned char *szIV, unsigned char *szDycMsg, int& nDycTotMsgLen)
{
	bool bRet = false;
	unsigned char szKey[16] = { 0xAE, 0xF4, 0x00, 0x06, 0x88, 0xB9, 0xCA, 0xF6, 0xE9, 0xF2, 0x28, 0x1B, 0x59, 0x8B, 0x36, 0x94 };
	//unsigned char szIV[16] = { 0xF0, 0xCE, 0xF9, 0x39, 0x2F, 0x94, 0xD1, 0xB8, 0x61, 0x12, 0x3B, 0xFE, 0x96, 0x87, 0x88, 0xE7 };

	EVP_CIPHER_CTX* pEVPAESCBCDecCtx = NULL;
	//cout << "EVP_CIPHER_CTX_new" << endl;
	pEVPAESCBCDecCtx = EVP_CIPHER_CTX_new();

	//cout << "EVP_CipherInit_ex" << endl;
	EVP_CipherInit_ex(pEVPAESCBCDecCtx, EVP_aes_128_cbc(), NULL, szKey, szIV, 0);
	//EVP_CIPHER_CTX_set_padding(pEVPAESCBCDecCtx, 0);
	int nDycMsgen = 0;

	//cout << "EVP_CipherUpdate" << endl;
	if (1 == EVP_CipherUpdate(pEVPAESCBCDecCtx, szDycMsg, &nDycMsgen, byCipher, nCipherLen))
	{
		nDycTotMsgLen += nDycMsgen;
		//cout << "EVP_CipherFinal_ex" << endl;
		if (1 == EVP_CipherFinal_ex(pEVPAESCBCDecCtx, szDycMsg + nDycMsgen, &nDycTotMsgLen))
		{
			nDycTotMsgLen += nDycMsgen;
			bRet = true;
		}
	}
	//cout << "EVP_CIPHER_CTX_free" << endl;
	EVP_CIPHER_CTX_free(pEVPAESCBCDecCtx);

	//if (bRet)
	//{
		//cout << "Decrypted message" << endl;
		//BIO_dump_fp(stdout, (const char*)szDycMsg, nDycTotMsgLen);
	//}

	return bRet;
}

bool Validate(unsigned char *szDycMsg, int nDycMsgLen)
{
	//cout << "Validate" << endl;

	//cout << "Decrypted message" << endl;
	//BIO_dump_fp(stdout, (const char*)szDycMsg, nDycMsgLen);
	bool bRet = false;

	unsigned char szPassPhrase[] = { "God is good always & every time." };
	int nPassPhraseLen = strlen((const char*)szPassPhrase);
	//cout << "Actual message" << endl;
	//BIO_dump_fp(stdout, (const char*)szPassPhrase, nPassPhraseLen);

	// I am commenting this for the demonstration of timming attack.
	// But Even this does not solve the attack problem.
	//if (nPassPhraseLen != nEncMsgLen)
	//	return bRet;

	//int nCmp = (nPassPhraseLen < nDycMsgLen)?nPassPhraseLen:nDycMsgLen;
	//if (memcmp(szPassPhrase, szDycMsg, nCmp) == 0)
	if (memcmp(szPassPhrase, szDycMsg, nPassPhraseLen) == 0)
	{
		bRet = true;
		cout << "true" << endl;
	}

	return bRet;
}

int main(int argc, char const* argv[])
{
       int server_fd, new_socket;
       struct sockaddr_in address;
       int opt = 1;
       int addrlen = sizeof(address);

       cout << "socket" << endl;
       // Creating socket file descriptor
       if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
       {
               perror("socket failed");
               exit(EXIT_FAILURE);
       }

       cout << "setsockopt" << endl;
       // Forcefully attaching socket to port 8080
       if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)))
       {
               perror("setsockopt");
               exit(EXIT_FAILURE);
       }
       address.sin_family = AF_INET;
       address.sin_addr.s_addr = INADDR_ANY;
       address.sin_port = htons(PORT);

       cout << "bind" << endl;
       // Forcefully attaching socket to port 8080
       if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0)
       {
               perror("bind failed");
               exit(EXIT_FAILURE);
       }
       cout << "listen" << endl;
       if (listen(server_fd, 3) < 0)
       {
               perror("listen");
               exit(EXIT_FAILURE);
       }
       cout << "accept" << endl;
       if ((new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen)) < 0)
       {
               perror("accept");
               exit(EXIT_FAILURE);
       }
       //valread = read(new_socket, buffer, 1024);
       //printf("%s\n", buffer);
       //send(new_socket, hello, strlen(hello), 0);
       //printf("Hello message sent\n");
       //while(1)
       //{
       //    cout << "read" << endl;
       //    valread = read(new_socket, buffer, 1024);
       //    if (strcmp(buffer, "q") == 0) break;
       //    printf("%s\n", buffer);
       //    cout << "send" << endl;
       //    send(new_socket, hello, strlen(hello), 0);
       //    printf("message sent\n");
       //}
       unsigned char szCipher[1024] = { 0 };
       int nCipherLen = 0;
       unsigned char szEncMsg[1024] = { 0 };
       int nEncMsgLen = 0;
       while(1)
       {
           //cout << "read" << endl;
           nCipherLen = read(new_socket, szCipher, 1024);
           //cout << "The captured cipher text" << endl;
           //BIO_dump_fp(stdout, (const char*)szCipher, nCipherLen);

           memset(szEncMsg, 0, 1024);

           int nStatus = enumErrors::SUCCESS;
           if (false == DecryptCipher((unsigned char*)szCipher + 0x10/*Exclude the IV*/, nCipherLen - 0x10 /*Encrypted block without IV*/,
        		   szCipher/*IV*/, (unsigned char*)szEncMsg, nEncMsgLen))
           {
               //cout << "send Decryption error." << endl;
               //nStatus = enumErrors::DECRYPTIONERROR;
               nStatus = enumErrors::FAILUER;
           }

           if (enumErrors::SUCCESS == nStatus)
           {
			   if (false == Validate(szEncMsg, nEncMsgLen))
			   {
				   //cout << "send authentication error." << endl;
				   //nStatus = enumErrors::AUTHERROR;
				   nStatus = enumErrors::FAILUER;
			   }
           }

           //cout << "send" << endl;
           send(new_socket, (void*)&nStatus, sizeof(int), 0);
           //printf("message sent\n");
           //if (enumErrors::SUCCESS == nStatus)
           //break;

           //cout << endl;
       }

       // closing the connected socket
       close(new_socket);
       // closing the listening socket
       shutdown(server_fd, SHUT_RDWR);
       return 0;
}
