/*
 * Source1.cpp
 *
 *  Created on: May 20, 2023
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

#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509err.h>

int main()
{
	BIO* pBIOX509 = NULL;
	pBIOX509 = BIO_new_file("X509.pem", "rb");
	X509* pX509 = NULL;
	PEM_read_bio_X509(pBIOX509, &pX509, NULL, NULL);
	BIO_free(pBIOX509);

	BIO* pBIOPriv = NULL;
	pBIOPriv = BIO_new_file("X509Priv.pem", "rb");
	EVP_PKEY* pEVPPKEY = NULL;
	PEM_read_bio_PrivateKey(pBIOPriv, &pEVPPKEY, NULL, NULL);
	BIO_free(pBIOPriv);

	EVP_PKEY* pEVPPKEYPub = NULL;
	pEVPPKEYPub = X509_get0_pubkey(pX509);

	if (X509_verify(pX509, pEVPPKEYPub))
	{
		BIO* pBIOStdout = NULL;
		pBIOStdout = BIO_new_fp(stdout, 0);
		X509_print(pBIOStdout, pX509);
		BIO_free(pBIOStdout);
	}

	return 0;
}
