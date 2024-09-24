/*
 * Source1.cpp
 *
 *  Created on: May 16, 2023
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
#include <openssl/x509err.h>

int main()
{
	// Create RSA key
	EVP_PKEY* pEVPPKEY = NULL;
	EVP_PKEY_CTX* pEVPPKEYCTX = NULL;
	pEVPPKEYCTX = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	EVP_PKEY_keygen_init(pEVPPKEYCTX);
	EVP_PKEY_CTX_set_rsa_keygen_bits(pEVPPKEYCTX, 2048);
	EVP_PKEY_keygen(pEVPPKEYCTX, &pEVPPKEY);
	EVP_PKEY_CTX_free(pEVPPKEYCTX);

	X509* x509 = NULL;

	x509 = X509_new();
	X509_set_version(x509, 0L);
	//ASN1_INTEGER* pASN1SerialNumber = X509_get_serialNumber(x509);
	//ASN1_INTEGER_set(pASN1SerialNumber, 1L);
	ASN1_INTEGER_set(X509_get_serialNumber(x509), 1L);

	time_t tNow = time(NULL);
	X509_set1_notBefore(x509, X509_time_adj_ex(NULL, 0, 0, &tNow));
	time_t tAfter = tNow + 31536000;
	ASN1_TIME* pASN1TIME =  X509_time_adj_ex(NULL, 0, 0L, &tAfter);
	X509_set1_notAfter(x509, pASN1TIME);

	X509_NAME* pname;
	pname = X509_NAME_new();
	X509_NAME_add_entry_by_txt(pname, (const char*)"CN", MBSTRING_ASC, (const unsigned char*)"Ramnath", -1, -1, 0);
	X509_NAME_add_entry_by_txt(pname, (const char*)"O", MBSTRING_ASC, (const unsigned char*)"Ramnath", -1, -1, 0);
	X509_NAME_add_entry_by_txt(pname, (const char*)"OU", MBSTRING_ASC, (const unsigned char*)"Ramnath", -1, -1, 0);
	X509_NAME_add_entry_by_txt(pname, (const char*)"L", MBSTRING_ASC, (const unsigned char*)"Ramnath", -1, -1, 0);
	X509_NAME_add_entry_by_txt(pname, (const char*)"S", MBSTRING_ASC, (const unsigned char*)"Ramnath", -1, -1, 0);
	X509_NAME_add_entry_by_txt(pname, (const char*)"C", MBSTRING_ASC, (const unsigned char*)"Ramnath", -1, -1, 0);

	X509_set_subject_name(x509, pname);
	X509_set_issuer_name(x509, pname);

	X509_set_pubkey(x509, pEVPPKEY);

	X509_sign(x509, pEVPPKEY, EVP_sha256());

	BIO* pBIOOut = NULL;
	pBIOOut = BIO_new_file("X509.pem", "wb");
	PEM_write_bio_X509(pBIOOut, x509);
	BIO_free(pBIOOut);

	pBIOOut = BIO_new_file("X509Priv.pem", "wb");
	PEM_write_bio_PrivateKey(pBIOOut, pEVPPKEY, NULL, NULL, 0, NULL, NULL);
	BIO_free(pBIOOut);

	X509_NAME_free(pname);
	X509_free(x509);
	EVP_PKEY_free(pEVPPKEY);
	return 0;
}
