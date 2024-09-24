/*
 * Source.cpp
 *
 *  Created on: Jul 9, 2023
 *      Author: Ramnath
 */

#include <stdio.h>
#include <string.h>

#include <iostream>
using namespace std;

#include <openssl/err.h>

#include <openssl/bio.h>
#include <openssl/bioerr.h>

#include <openssl/evp.h>
#include <openssl/evperr.h>

int main()
{
	unsigned char szPass[] = { "strongestpassword" };
	cout << "Password:" << endl;
	BIO_dump_fp(stdout, (const char*)szPass, strlen((const char*)szPass));
	cout << endl << endl;
	unsigned char szKey[16];
	PKCS5_PBKDF2_HMAC((const char*)szPass, strlen((const char*)szPass), NULL, 0, 5, EVP_md5(), 16, szKey);
	cout << "Key derived from password using MD5:" << endl;
	BIO_dump_fp(stdout, (const char*)szKey, 16);
	cout << endl << endl;

	unsigned char szMessage[] = { "Pay Bob 1 dollar" };
	cout << "Transaction message:" << endl;
	BIO_dump_fp(stdout, (const char*)szMessage, strlen((const char*)szMessage));
	cout << endl << endl;
	unsigned char szCipher[16];
	int nCipherLen = 0;
	int nTotCipherLen = 0;

	//EVP_CIPHER_CTX_init();
	EVP_CIPHER_CTX* pAES128Ctx = EVP_CIPHER_CTX_new();;
	EVP_EncryptInit(pAES128Ctx, EVP_aes_128_ctr(), szKey, NULL);
	EVP_EncryptUpdate(pAES128Ctx, szCipher, &nCipherLen, szMessage, strlen((const char*)szMessage));
	nTotCipherLen = nCipherLen;
	nCipherLen = 0;
	EVP_EncryptFinal(pAES128Ctx, szCipher, &nCipherLen);
	nTotCipherLen += nCipherLen;
	EVP_CIPHER_CTX_free(pAES128Ctx);
	cout << "Encrypted message:" << endl;
	BIO_dump_fp(stdout, (const char*)szCipher, nTotCipherLen);
	cout << "If you pass this cipher over the network," << endl << "attacker Bob (Man-In-The-Middle) may capture and modify 9th encrypted byte and send the encrypted transaction!" << endl;
	cout << endl << endl;

	// MAN-IN-THE-MIDDLE ATTACK mofified the 9th byte and increase the value.
	szCipher[8] ^= 0x01; // Remove One dollar.
	szCipher[8] ^= 0x09; // Add Nine dollar.

	cout << "Modified Encrypted message:" << endl;
	BIO_dump_fp(stdout, (const char*)szCipher, nTotCipherLen);
	cout << endl << endl;

	unsigned char szDycMsg[16];
	int nDycMsgLen = 0;
	int nTotDycMsgLen = 0;
	EVP_CIPHER_CTX* pMSG128Ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit(pMSG128Ctx, EVP_aes_128_ctr(), szKey, NULL);
	EVP_DecryptUpdate(pMSG128Ctx, szDycMsg, &nDycMsgLen, szCipher, nTotCipherLen);
	nTotDycMsgLen = nDycMsgLen;
	nDycMsgLen = 0;
	EVP_DecryptFinal(pMSG128Ctx, szDycMsg, &nDycMsgLen);
	nTotDycMsgLen += nDycMsgLen;
	EVP_CIPHER_CTX_free(pMSG128Ctx);

	cout << "Modified derypted message the bancker receives:" << endl;
	BIO_dump_fp(stdout, (const char*)szDycMsg, nTotDycMsgLen);
	cout << endl << endl;

	return 0;
}
