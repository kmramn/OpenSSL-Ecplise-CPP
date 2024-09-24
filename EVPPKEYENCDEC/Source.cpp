/*
 * Source.cpp
 *
 *  Created on: May 1, 2023
 *      Author: Ramnath
 */

#include <stdio.h>

#include <iostream>
using namespace std;

#include <openssl/evp.h>
#include <openssl/evperr.h>

#include <openssl/bio.h>
#include <openssl/bioerr.h>

#include <openssl/pem.h>
#include <openssl/pemerr.h>

#include <openssl/rsa.h>
#include <openssl/rsaerr.h>

/*int main()
{
	EVP_PKEY_CTX* pEVPPKEYCTX = NULL;
	EVP_PKEY* pEVPPKEY = NULL;

	pEVPPKEYCTX = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	EVP_PKEY_keygen_init(pEVPPKEYCTX);
	EVP_PKEY_CTX_set_rsa_keygen_bits(pEVPPKEYCTX, 2048);
	EVP_PKEY_keygen(pEVPPKEYCTX, &pEVPPKEY);

	BIO *pPKEYPriOutput = NULL;
	pPKEYPriOutput = BIO_new_file("EVPPKEYPRIKEY.pem", "wb");
	PEM_write_bio_PrivateKey(pPKEYPriOutput, pEVPPKEY, NULL, NULL, 0, NULL, NULL);
	BIO_free(pPKEYPriOutput);

	BIO *pPKEYPriStdout = NULL;
	pPKEYPriStdout = BIO_new_fp(stdout, 0);
	PEM_write_bio_PrivateKey(pPKEYPriStdout, pEVPPKEY, NULL, NULL, 0, NULL, NULL);
	EVP_PKEY_print_private(pPKEYPriStdout, pEVPPKEY, 0, NULL);
	BIO_free(pPKEYPriStdout);

	BIO *pPKEYPubOutput = NULL;
	pPKEYPubOutput = BIO_new_file("EVPPKEYPUBKEY.pem", "wb");
	PEM_write_bio_PUBKEY(pPKEYPubOutput, pEVPPKEY);
	BIO_free(pPKEYPubOutput);

	BIO *pPKEYPubStdout = NULL;
	pPKEYPubStdout = BIO_new_fp(stdout, 0);
	PEM_write_bio_PUBKEY(pPKEYPubStdout, pEVPPKEY);
	EVP_PKEY_print_public(pPKEYPubStdout, pEVPPKEY, 0, NULL);
	BIO_free(pPKEYPubStdout);

	//EVP_PKEY_id(pEVPPKEY);
	//EVP_PKEY_type(type)
	EVP_PKEY_free(pEVPPKEY);
	EVP_PKEY_CTX_free(pEVPPKEYCTX);

	return 0;
}*/
