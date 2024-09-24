/*
 * Source1.cpp
 *
 *  Created on: May 8, 2023
 *      Author: Ramnath
 */

#include <stdio.h>
#include <string.h>

#include <iostream>
using namespace std;

#include <openssl/err.h>

#include <openssl/evp.h>
#include <openssl/evperr.h>

#include <openssl/bio.h>
#include <openssl/bioerr.h>

#include <openssl/pem.h>
#include <openssl/pemerr.h>

int main()
{
	// Generate Private Key
	BIO* pbioPrivOut = NULL;
	pbioPrivOut = BIO_new_file("EVPPKEYPRIKEY.pem", "wb");
	BIO* pbioPubOut = NULL;
	pbioPubOut = BIO_new_file("EVPPKEYPUBKEY.pem", "wb");
	EVP_PKEY* pEVPPKEY = NULL;
	pEVPPKEY = EVP_PKEY_new();
	EVP_PKEY_CTX* pEVPPKEYCTX = NULL;
	pEVPPKEYCTX = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	EVP_PKEY_keygen_init(pEVPPKEYCTX);
	EVP_PKEY_CTX_set_rsa_keygen_bits(pEVPPKEYCTX, 2048);
	EVP_PKEY_keygen(pEVPPKEYCTX, &pEVPPKEY);
	//EVP_PKEY_print_private(pbioPrivOut, pEVPPKEY, 0, NULL);
	PEM_write_bio_PrivateKey(pbioPrivOut, pEVPPKEY, NULL, NULL, 0, NULL, NULL);
	PEM_write_bio_PUBKEY(pbioPubOut, pEVPPKEY);
	//PEM_write_bio_PUBKEY(pbioPrivOut, pEVPPKEY);
	EVP_PKEY_CTX_free(pEVPPKEYCTX);
	EVP_PKEY_free(pEVPPKEY);
	BIO_free(pbioPubOut);
	BIO_free(pbioPrivOut);

	// Generate message digest
	BIO* pBIOPRIV = NULL;
	EVP_PKEY* pEVPPKEYPriv = NULL;
	pBIOPRIV = BIO_new_file("EVPPKEYPRIKEY.pem", "rb");
	PEM_read_bio_PrivateKey(pBIOPRIV, &pEVPPKEYPriv, NULL, NULL);
	BIO_free(pBIOPRIV);

	EVP_MD* pEVPMD = NULL;
	pEVPMD = (EVP_MD*)EVP_get_digestbyname((const char*)"SHA256");
	EVP_MD_CTX* pEVPMDCTXSign = EVP_MD_CTX_new();
	EVP_DigestInit(pEVPMDCTXSign, pEVPMD);
	// or
	//EVP_DigestInit_ex(pEVPMDCTXSign, EVP_sha256(), impl)
	char szBuff1[] = { "God is great all the time." };
	EVP_DigestUpdate(pEVPMDCTXSign, (void *)szBuff1, (size_t)strlen(szBuff1));
	unsigned char szMD[32];
	unsigned int nMDLen = 32;
	EVP_DigestFinal(pEVPMDCTXSign, szMD, &nMDLen);
	//EVP_MD_fr
	EVP_MD_CTX_free(pEVPMDCTXSign);
	BIO_dump_fp(stdout, (const char*)szMD, (int)nMDLen);

	// Sign message digest using private key
	cout << "1" <<  endl;
	EVP_PKEY_CTX* pEVPPKEYCtxPriv = NULL;
	cout << "2" <<  endl;
	pEVPPKEYCtxPriv = EVP_PKEY_CTX_new(pEVPPKEYPriv, NULL);
	ERR_print_errors_fp(stdout);
	cout << "3" <<  endl;
	//EVP_PKEY_CTX_md(pEVPPKEYCtxPriv, 0, 0, "SHA256");
	EVP_PKEY_sign_init(pEVPPKEYCtxPriv);
	ERR_print_errors_fp(stdout);
	cout << "5" <<  endl;
	EVP_PKEY_CTX_set_rsa_padding(pEVPPKEYCtxPriv,  RSA_PKCS1_PADDING);
	ERR_print_errors_fp(stdout);
	cout << "4" <<  endl;
	EVP_PKEY_CTX_set_signature_md(pEVPPKEYCtxPriv, EVP_sha256());
	ERR_print_errors_fp(stdout);
	size_t siglen = 0;
	cout << "6" <<  endl;
	EVP_PKEY_sign(pEVPPKEYCtxPriv, NULL, &siglen, szMD, nMDLen);
	cout << "7-" << szMD << nMDLen << siglen <<  endl;
	ERR_print_errors_fp(stdout);
	unsigned char* szSig = (unsigned char*)OPENSSL_malloc(siglen);
	cout << "8" <<  endl;
	EVP_PKEY_sign(pEVPPKEYCtxPriv, szSig, &siglen, szMD, nMDLen);
	cout << "9" <<  endl;
	BIO_dump_fp(stdout, (const char*)szSig, (int)siglen);
	cout << "10" <<  endl;
	EVP_PKEY_CTX_free(pEVPPKEYCtxPriv);

	cout << "12" <<  endl;
	EVP_PKEY_free(pEVPPKEYPriv);


	// Read public key
	BIO* pBIOPUCOut = NULL;
	pBIOPUCOut = BIO_new_file("EVPPKEYPUBKEY.pem", "rb");
	EVP_PKEY* pEVPPKEYPub = NULL;
	PEM_read_bio_PUBKEY(pBIOPUCOut, &pEVPPKEYPub, NULL, NULL);
	BIO_free(pBIOPUCOut);

	//// Calculate the digest
	//EVP_MD_CTX* pMDCTXPUB = EVP_MD_CTX_new();
	////EVP_MD* pMDPUB = (EVP_MD*)EVP_get_digestbyname((const char*)"SHA256");
	////EVP_DigestInit_ex(pMDCTXPUB, pMDPUB, NULL);
	//EVP_DigestInit_ex(pMDCTXPUB, EVP_sha256(), NULL);
	char szBuff2[] = { "God is great all the time." };
	//EVP_DigestUpdate(pMDCTXPUB, (const void*)szBuff2, strlen(szBuff2));
	//unsigned char szMD2[32];
	//unsigned int nMD2Len = 32;
	//EVP_DigestFinal(pMDCTXPUB, szMD2, &nMD2Len);
	//EVP_MD_CTX_free(pMDCTXPUB);
	//BIO_dump_fp(stdout, (const char*)szMD2, nMD2Len);

	// Verify signature
	/*EVP_MD_CTX* pEVPMDCTX = EVP_MD_CTX_new();
	EVP_VerifyInit_ex(pEVPMDCTX, EVP_sha256(), NULL);
	EVP_VerifyUpdate(pEVPMDCTX, (const void*)szBuff2, strlen(szBuff2) + 1);
	if (EVP_VerifyFinal(pEVPMDCTX, szSig, siglen, pEVPPKEYPub)) {
		cout << "Verified successfully" << endl;
	} else {
		cout << "Verified failed" << endl;
	}
	EVP_MD_CTX_free(pEVPMDCTX);*/

	EVP_PKEY_CTX* pEVPPKEYCTXPub = NULL;
	pEVPPKEYCTXPub = EVP_PKEY_CTX_new(pEVPPKEYPub, NULL);
	EVP_PKEY_verify_init(pEVPPKEYCTXPub);
	EVP_PKEY_CTX_set_rsa_padding(pEVPPKEYCTXPub, RSA_PKCS1_PADDING);
	EVP_PKEY_CTX_set_signature_md(pEVPPKEYCTXPub, EVP_sha256());
	if (EVP_PKEY_verify(pEVPPKEYCTXPub, szSig, siglen, szMD, nMDLen)) {
		cout << "Verified successfully" << endl;
	} else {
		cout << "Verified failed" << endl;
	}
	EVP_PKEY_CTX_free(pEVPPKEYCTXPub);

	OPENSSL_free(szSig);

	return 0;
}
