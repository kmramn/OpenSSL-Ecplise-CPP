/*
 * Source.cpp
 *
 *  Created on: Apr 16, 2023
 *      Author: Ramnath
 */

#include <stdio.h>
#include <string.h>

#include <iostream>
using namespace std;

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/evperr.h>

int main()
{
	EVP_CIPHER_CTX* evpEnCiCtx = NULL;
	evpEnCiCtx = EVP_CIPHER_CTX_new();
	unsigned char szKey[32] = { 0x30, 0xE8, 0xEA, 0x50, 0xBE, 0xAB, 0x3D, 0xAF, 0x33, 0x5E, 0xB5, 0xDF, 0x16, 0x9C, 0xDF, 0xD8, 0x25, 0x9D, 0xF4, 0x75, 0x05, 0xDB, 0x23, 0x7C, 0xBB, 0x19, 0x43, 0x7E, 0xB3, 0x35, 0x39, 0xB2 };
	unsigned char sziv[16] = { 0xC0, 0xC7, 0x83, 0x4D, 0x30, 0xF6, 0xCE, 0x56, 0xC0, 0x98, 0x5D, 0xE6, 0x51, 0x5D, 0xBC, 0x12 };
	EVP_EncryptInit(evpEnCiCtx, EVP_aes_256_cbc(), szKey, sziv);
	unsigned char szInText[] = { "God is great all the time. All the time God is great......................................" };
	//unsigned char szInText[] = { "" };
	int nInLen = strlen((const char *)szInText);
	unsigned char szCipText[512];
	memset(szCipText, 0, 512);
	int nOutLen = 0;
	int nCipherLen = 0;
	EVP_EncryptUpdate(evpEnCiCtx, szCipText, &nOutLen,  szInText, nInLen);
	nCipherLen += nOutLen;
	EVP_EncryptFinal(evpEnCiCtx, szCipText + nCipherLen, &nOutLen);
	nCipherLen += nOutLen;
	BIO_dump_fp(stdout, (const char*)szCipText, nCipherLen);
	EVP_CIPHER_CTX_free(evpEnCiCtx);

	EVP_CIPHER_CTX* evpDyCiCtx = NULL;
	evpDyCiCtx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit(evpDyCiCtx, EVP_aes_256_cbc(), szKey, sziv);
	unsigned char szPlainText[512];
	memset(szPlainText, 0, 512);
	nOutLen = 0;
	int nPlainLen = 0;
	EVP_DecryptUpdate(evpDyCiCtx, szPlainText, &nOutLen, szCipText, nCipherLen);
	nPlainLen += nOutLen;
	EVP_DecryptFinal(evpDyCiCtx, szPlainText + nPlainLen, &nOutLen);
	nPlainLen += nOutLen;
	szPlainText[nPlainLen] = 0;
	cout << nPlainLen << endl;
	EVP_CIPHER_CTX_free(evpDyCiCtx);
	cout << szPlainText << endl;
	return 0;
}

