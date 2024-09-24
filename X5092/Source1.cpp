
#include <stdio.h>

#include <iostream>
using namespace std;

#include <openssl/crypto.h>

#include <openssl/err.h>

#include <openssl/bio.h>
#include <openssl/bioerr.h>

#include <openssl/evp.h>
#include <openssl/evperr.h>

#include <openssl/x509.h>
#include <openssl/x509err.h>

#include <openssl/bn.h>
#include <openssl/bnerr.h>

//#include <openssl/dh.h>

#include <openssl/opensslv.h>

int main()
{
	X509* pX509SelfSignedCert;

	//X509
	//OPENSSL_VERSION_NUMBER

	//EVP_PKEY_CTX* pDH = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);

	cout << SSLeay_version(SSLEAY_VERSION) << endl;

	cout << "1" << endl;
	EVP_PKEY_CTX* pDHCtx = NULL;
	//pDHCtx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
	//pDHCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
	//cout << "2" << endl;
	//EVP_PKEY_keygen_init(pDHCtx);
	//cout << "3" << endl;
	//EVP_PKEY_CTX_set_dh_paramgen_prime_len(pDHCtx, 2048);
	//cout << "4" << endl;
	//EVP_PKEY_CTX_set_dh_paramgen_generator(pDHCtx, 2);
	//cout << "5" << endl;
	EVP_PKEY* params = NULL;
	  // Initalise Diffie Hellman parameter PKEY
	    if(NULL == (params = EVP_PKEY_new())) {
	        std::cout << "error 3" << std::endl;
	    }

	    // Set Diffie Hellman paramerers
	    if(1 != EVP_PKEY_set1_DH(params, DH_get_1024_160())) {
	        std::cout << "error 4" << std::endl;
	    }

	    // Initalise client 1 PKEY Context
	    if(!(pDHCtx = EVP_PKEY_CTX_new(params, NULL))) {
	        std::cout << "error 5" << std::endl;
	    }
		EVP_PKEY_keygen_init(pDHCtx);

	EVP_PKEY* pkey = NULL;
	EVP_PKEY_keygen(pDHCtx, &pkey);
	cout << "6" << endl;
	ERR_print_errors_fp(stdout);
	cout << "7" << endl;

	BIO* pBIO = BIO_new_fp(stdout, 0);
	cout << "8" << endl;
	EVP_PKEY_print_params(pBIO, pkey, 0, NULL);
	cout << "9" << endl;
	//BIGNUM* prime = NULL;
	//BIGNUM* generator = NULL;
	//EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_P, &prime);
	//EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_G, &generator);
	//cout << "p" << endl;
	//BN_print_fp(stdout, prime);
	//cout << endl << "g" << endl;
	//BN_print_fp(stdout, generator);
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(pDHCtx);

	return 0;
}
