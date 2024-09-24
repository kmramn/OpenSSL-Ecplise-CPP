/*
 * Source.cpp
 *
 *  Created on: Apr 17, 2023
 *      Author: Ramnath
 */

#include <stdio.h>
#include <string.h>

#include <iostream>
using namespace std;

#include <openssl/evp.h>
#include <openssl/evperr.h>
#include <openssl/bio.h>
#include <openssl/bioerr.h>

int main()
{
	BIO* pbioIn = BIO_new_file("Source.cpp", "r");
	BIO* pbioOut = BIO_new_file("Source.md", "wb");
	EVP_MD_CTX* pEVPMDCTX = NULL;
	pEVPMDCTX = EVP_MD_CTX_new();
	EVP_MD* pEVPMD = NULL;
	const char szMDAlgo[] = { "sha512" };
	//(EVP_MD*)EVP_md2();;
	pEVPMD = (EVP_MD*)EVP_get_digestbyname(szMDAlgo);
	EVP_DigestInit(pEVPMDCTX, pEVPMD);
	//unsigned char szMessage[] = { "ABCEDF" };
	unsigned char szMessage[2048];
	int nMsgLen = strlen((const char*)szMessage);
	nMsgLen = BIO_read(pbioIn, szMessage, 2048);
	EVP_DigestUpdate(pEVPMDCTX, szMessage, nMsgLen);
	unsigned char szMD[1024];
	unsigned int nMDLen = 0;
	EVP_DigestFinal(pEVPMDCTX, szMD, &nMDLen);
	EVP_MD_CTX_free(pEVPMDCTX);
	BIO_dump_fp(stdout, (const char*)szMD, nMDLen);
	BIO_write(pbioOut, szMD, nMDLen);
	BIO_free(pbioIn);
	BIO_free(pbioOut);
}
