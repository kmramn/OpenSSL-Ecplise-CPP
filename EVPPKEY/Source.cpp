/*
 * Source.cpp
 *
 *  Created on: Apr 18, 2023
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

#include <openssl/rsa.h>
#include <openssl/rsaerr.h>

#include <openssl/pem.h>
#include <openssl/pemerr.h>

int main()
{
	EVP_PKEY* pEVPPKEY = NULL;

	EVP_PKEY_CTX* pEVPPKEYCTX = NULL;
	pEVPPKEYCTX = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	EVP_PKEY_CTX_set_rsa_keygen_bits(pEVPPKEYCTX, 2048);
	EVP_PKEY_keygen_init(pEVPPKEYCTX);
	EVP_PKEY_keygen(pEVPPKEYCTX, &pEVPPKEY);
	cout << "Size : " << EVP_PKEY_size(pEVPPKEY) << endl;
	cout << "Bits : " << EVP_PKEY_bits(pEVPPKEY) << endl;
	cout << "Id : " << EVP_PKEY_id(pEVPPKEY) << endl;
	cout << "Type : " << EVP_PKEY_type(EVP_PKEY_id(pEVPPKEY)) << endl;
	BIO* pbioOutPublic = NULL;
	pbioOutPublic = BIO_new_file("E:\\Ramnath\\EclipseCPP\\workspace\\EVPPKEY\\EVPPublic.pem", "wb");
	BIO* pbioStdOutPublic = BIO_new_fp(stdout, 0);
	EVP_PKEY_print_public(pbioOutPublic, pEVPPKEY, 0, NULL);
	EVP_PKEY_print_public(pbioStdOutPublic, pEVPPKEY, 0, NULL);

	BIO* pbioOutPublicPEM = NULL;
	pbioOutPublicPEM = BIO_new_file("E:\\Ramnath\\EclipseCPP\\workspace\\EVPPKEY\\EVPPublicPEM.pem", "wb");
	PEM_write_bio_PUBKEY(pbioOutPublicPEM, pEVPPKEY);
	BIO_free(pbioOutPublicPEM);

	BIO_free(pbioStdOutPublic);
	BIO_free(pbioOutPublic);

	BIO* pbioOutPrivate = NULL;
	pbioOutPrivate = BIO_new_file("E:\\Ramnath\\EclipseCPP\\workspace\\EVPPKEY\\EVPPrivate.pem", "wb");
	EVP_PKEY_print_private(pbioOutPrivate, pEVPPKEY, 0, NULL);

	BIO* pbioOutPivatePEM = NULL;
	pbioOutPivatePEM = BIO_new_file("E:\\Ramnath\\EclipseCPP\\workspace\\EVPPKEY\\EVPPrivatePEM.pem", "wb");
	PEM_write_bio_PrivateKey(pbioOutPivatePEM, pEVPPKEY, NULL, NULL, 0, NULL, NULL);
	BIO_free(pbioOutPivatePEM);

	BIO_free(pbioOutPrivate);
	EVP_PKEY_CTX_free(pEVPPKEYCTX);
	EVP_PKEY_free(pEVPPKEY);

	BIO* pbioInputPublic = NULL;
	pbioInputPublic = BIO_new_file("E:\\Ramnath\\EclipseCPP\\workspace\\EVPPKEY\\EVPPrivatePEM.pem", "rb");
	EVP_PKEY* pEvpPkey1 = NULL;
	//pEvpPkey1 = PEM_read_bio_PUBKEY(pbioInputPublic, NULL, NULL, NULL);
	cout << "1" << endl;
	pEvpPkey1 = PEM_read_bio_PUBKEY(pbioInputPublic, &pEvpPkey1, NULL, NULL);
	cout << "2" << endl;
	if (pEvpPkey1 != NULL) {
		pbioStdOutPublic = NULL;
		pbioStdOutPublic = BIO_new_fp(stdout, 0);
		EVP_PKEY_print_public(pbioStdOutPublic, pEvpPkey1, 0, NULL);
		BIO_free(pbioStdOutPublic);
	}
	EVP_PKEY_free(pEvpPkey1);
	BIO_free(pbioInputPublic);
}
