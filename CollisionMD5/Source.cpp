/*
 * Source.cpp
 *
 *  Created on: Jul 24, 2023
 *      Author: Ramnath
 */

#include <stdio.h>

#include <iostream>
#include <vector>
using namespace std;

#include <gmp.h>
#include <gmpxx.h>

#include <openssl/err.h>

#include <openssl/bio.h>
#include <openssl/bioerr.h>

#include <openssl/md5.h>

#include <openssl/evp.h>
#include <openssl/evperr.h>

int main()
{
	mpz_class mpzData = 0;
	EVP_MD_CTX* pMDCtx = EVP_MD_CTX_new();
	EVP_MD_CTX* pMDCtx1 = NULL;
	EVP_MD_CTX_copy_ex(pMDCtx, pMDCtx1);
	EVP_DigestInit_ex(pMDCtx, EVP_md5(), NULL);
	mpzData.get_str(16).c_str();
	unsigned char szData[1];
	cout << mpzData.get_str(16) << endl;
	EVP_DigestUpdate(pMDCtx, mpzData.get_str(16).c_str(), 1);
	unsigned char szMD[16];
	unsigned int nMDLen = 0;
	EVP_DigestFinal_ex(pMDCtx, szMD, &nMDLen);
	BIO_dump_fp(stdout, (const char*)szMD, nMDLen);
	//EVP_MD_CTX_copy_ex(out, in)
	//EVP_MD_CTX_free(pMDCtx);

	//pMDCtx = EVP_MD_CTX_new();
	EVP_MD_CTX_reset(pMDCtx);
	EVP_DigestInit_ex(pMDCtx, EVP_md5(), NULL);
	szData[0]++;
	mpzData++;
	//EVP_MD_CTX_copy_ex(pMDCtx1, pMDCtx);
	cout << mpzData.get_str(16) << endl;
	EVP_DigestUpdate(pMDCtx, mpzData.get_str(16).c_str(), 1);
	nMDLen = 0;
	EVP_DigestFinal_ex(pMDCtx, szMD, &nMDLen);
	BIO_dump_fp(stdout, (const char*)szMD, nMDLen);
	EVP_MD_CTX_free(pMDCtx);

	return 0;
}
