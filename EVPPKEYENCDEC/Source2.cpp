/*
 * Source2.cpp
 *
 *  Created on: May 1, 2023
 *      Author: Ramnath
 */

#include <stdio.h>
#include <string.h>
#include <cstring>

#include <iostream>
using namespace std;

#include <openssl/evp.h>
#include <openssl/evperr.h>

#include <openssl/bio.h>
#include <openssl/bioerr.h>

#include <openssl/pem.h>
#include <openssl/pemerr.h>

int main()
{
	BIO* pEVPKEYInput = NULL;
	EVP_PKEY* pEVPPKEYPub = NULL;
	EVP_PKEY* pEVPPKEYPri = NULL;

	pEVPKEYInput = BIO_new_file("EVPPKEYPUBKEY.pem", "rb");
	PEM_read_bio_PUBKEY(pEVPKEYInput, &pEVPPKEYPub, NULL, NULL);
	BIO_free(pEVPKEYInput);

	pEVPKEYInput = BIO_new_file("EVPPKEYPRIKEY.pem", "rb");
	PEM_read_bio_PrivateKey(pEVPKEYInput, &pEVPPKEYPri, NULL, NULL);
	BIO_free(pEVPKEYInput);

	BIO* pEVPKEYStdout = BIO_new_fp(stdout, 0);
	PEM_write_bio_PUBKEY(pEVPKEYStdout, pEVPPKEYPub);
	EVP_PKEY_print_public(pEVPKEYStdout, pEVPPKEYPub, 0, NULL);
	PEM_write_bio_PrivateKey(pEVPKEYStdout, pEVPPKEYPri, NULL, NULL, 0, NULL, NULL);
	EVP_PKEY_print_private(pEVPKEYStdout, pEVPPKEYPri, 0, NULL);
	BIO_free(pEVPKEYStdout);

	EVP_PKEY_CTX* pEVPPKEYCtx = NULL;
	pEVPPKEYCtx = EVP_PKEY_CTX_new(pEVPPKEYPub, NULL);
	EVP_PKEY_encrypt_init(pEVPPKEYCtx);

	unsigned char szBuffer[] = { "God is there all the time. All the time God is there." };
	unsigned long szBuffLen = strlen((const char*)szBuffer);
	unsigned long szEncBuffLen = 0;
	cout << szBuffer << " " << szBuffLen << endl;
	EVP_PKEY_encrypt(pEVPPKEYCtx, NULL, &szEncBuffLen, szBuffer, szBuffLen);
	cout << "Encrypted buffer len " << szEncBuffLen << endl;
	unsigned char* pszEncBuff = NULL;
	pszEncBuff = (unsigned char*)OPENSSL_malloc(szEncBuffLen);
	if (EVP_PKEY_encrypt(pEVPPKEYCtx, pszEncBuff, &szEncBuffLen, szBuffer, szBuffLen))
	{
		BIO* pbioPrintStdout = NULL;
		pbioPrintStdout = BIO_new_fp(stdout, 0);
		BIO_printf(pbioPrintStdout, "%s", pszEncBuff);
		BIO_dump_fp(stdout, (const char*)pszEncBuff, szEncBuffLen);
		BIO_free(pbioPrintStdout);
	}
	EVP_PKEY_CTX_free(pEVPPKEYCtx);

	EVP_PKEY_CTX* pEVPPKEYCtxDec = NULL;
	pEVPPKEYCtxDec = EVP_PKEY_CTX_new(pEVPPKEYPri, NULL);

	EVP_PKEY_decrypt_init(pEVPPKEYCtxDec);
	size_t stDycLen = 0;
	EVP_PKEY_decrypt(pEVPPKEYCtxDec, NULL, &stDycLen, pszEncBuff, szEncBuffLen);
	unsigned char* pszDycBuff = NULL;
	pszDycBuff = (unsigned char*)OPENSSL_malloc(stDycLen + 1);
	memset(pszDycBuff, 0, stDycLen);
	EVP_PKEY_decrypt(pEVPPKEYCtxDec, pszDycBuff, &stDycLen, pszEncBuff, szEncBuffLen);
	cout << pszDycBuff << endl;
	EVP_PKEY_CTX_free(pEVPPKEYCtxDec);

	OPENSSL_free(pszEncBuff);

	EVP_PKEY_free(pEVPPKEYPub);
	EVP_PKEY_free(pEVPPKEYPri);
	return 0;
}
