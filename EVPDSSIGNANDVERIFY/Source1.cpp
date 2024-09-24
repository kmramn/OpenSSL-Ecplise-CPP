/*
 * Source1.cpp
 *
 *  Created on: May 5, 2023
 *      Author: Ramnath
 */

#include <stdio.h>
#include <string.h>

#include <iostream>
using namespace std;

#include <openssl/bio.h>
#include <openssl/bioerr.h>

#include <openssl/evp.h>
#include <openssl/evperr.h>

#include <openssl/dsa.h>
#include <openssl/dsaerr.h>

#include <openssl/pem.h>
#include <openssl/pemerr.h>

int main()
{
	EVP_MD_CTX* pEVPMDCTX = NULL;
	cout << "1" << endl;
	pEVPMDCTX = EVP_MD_CTX_new();
	EVP_MD* pEVPMD = NULL;
	cout << "1" << endl;
	pEVPMD = (EVP_MD*)EVP_get_digestbyname("SHA256");

	BIO* pBIOPub = NULL;
	BIO* pBIOPri = NULL;
	cout << "1" << endl;
	pBIOPub = BIO_new_file("EVPPKEYPUBKEY.pem", "rb");
	pBIOPri = BIO_new_file("EVPPKEYPRIKEY.pem", "rb");

	EVP_PKEY* pEVPPKEYPub = NULL;
	EVP_PKEY* pEVPPKEYPriv = NULL;
	cout << "3" << endl;
	PEM_read_bio_PUBKEY(pBIOPub, &pEVPPKEYPub, NULL, NULL);
	PEM_read_bio_PrivateKey(pBIOPri, &pEVPPKEYPriv, NULL, NULL);

	EVP_PKEY_CTX* pEVPPKEYCTX = NULL;
	cout << "3" << endl;
	EVP_DigestSignInit(pEVPMDCTX, &pEVPPKEYCTX, pEVPMD, NULL, pEVPPKEYPriv);
	unsigned char szSigNature[256];
	size_t stSigLen = 256;
	unsigned char szBuff[] = { "God is great all the time. All the time God is great." };
	cout << "4" << endl;
	EVP_DigestSign(pEVPMDCTX, szSigNature, &stSigLen, szBuff, strlen((const char*)szBuff));
	cout << "5" << endl;
	EVP_DigestSignFinal(pEVPMDCTX, szSigNature, &stSigLen);
	cout << "6" << endl;
	BIO_dump_fp(stdout, (const char*)szSigNature, stSigLen);

	//if (EVP_VerifyFinal(pEVPMDCTX, szSigNature, stSigLen, pEVPPKEYPub))
	//{
	//	cout << "Verified Successfully" << endl;
	//}

	cout << "7" << endl;
	//EVP_PKEY_CTX_free(pEVPPKEYCTX);
	BIO_free(pBIOPub);
	BIO_free(pBIOPri);
	//EVP_MD_free(pEVPMD);
	EVP_MD_CTX_free(pEVPMDCTX);

	EVP_MD_CTX* pEVPMSCTXV = NULL;
	pEVPMSCTXV = EVP_MD_CTX_new();
	EVP_MD* pEVPMDV = NULL;
	pEVPMDV = (EVP_MD*)EVP_get_digestbyname("SHA256");
	EVP_PKEY_CTX* pEVPPKEYCTXV = NULL;
	EVP_DigestVerifyInit(pEVPMSCTXV, &pEVPPKEYCTXV, pEVPMDV, NULL, pEVPPKEYPub);
	unsigned char szBuffV[] = { "God is great all the time. All the time God is great." };
	if (EVP_DigestVerify(pEVPMSCTXV, szSigNature, stSigLen, szBuffV, strlen((const char*)szBuff)))
	{
		cout << "Verified Successfully" << endl;
	}

	//EVP_PKEY_CTX_free(pEVPPKEYCTXV);
	//EVP_MD_free(pEVPMDV);
	EVP_MD_CTX_free(pEVPMSCTXV);
	EVP_PKEY_free(pEVPPKEYPub);
	EVP_PKEY_free(pEVPPKEYPriv);
	return 0;
}
