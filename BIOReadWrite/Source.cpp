/*
 * Source.cpp
 *
 *  Created on: Apr 15, 2023
 *      Author: Ramnath
 */

#include <stdio.h>
#include <string.h>
#include <memory.h>

#include <iostream>
using namespace std;

#include <openssl/ssl.h>
#include <openssl/bio.h>

int main()
{
	BIO* bioIn = NULL;
	BIO* bioOut = NULL;
	BIO* bioEnc64 = NULL;

	bioIn = BIO_new_file("E:\\Ramnath\\EclipseCPP\\workspace\\BIOReadWrite\\BIOTestIn.txt", "r");
	bioOut = BIO_new_file("E:\\Ramnath\\EclipseCPP\\workspace\\BIOReadWrite\\BIOTestOut.txt", "w");
	bioEnc64 = BIO_new(BIO_f_base64());
	BIO_push(bioEnc64, bioOut);

	char chBuffer[512];
	memset(chBuffer, 0, 512);
	int nLen = 0;
	int nLenOut = 0;
	while((nLen = BIO_read(bioIn, chBuffer, 512)) > 0)
	{
		nLenOut = BIO_write(bioEnc64, chBuffer, nLen);
	}

	BIO_free(bioIn);
	BIO_free(bioEnc64);

	return 0;
}


