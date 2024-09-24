/*
 * Source1.cpp
 *
 *  Created on: Aug 6, 2023
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
	EVP_CIPHER_CTX* pevpAESCBCEncCtx = NULL;
	pevpAESCBCEncCtx = EVP_CIPHER_CTX_new();

	unsigned char szKey[16] = { 0xAE, 0xF4, 0x00, 0x06, 0x88, 0xB9, 0xCA, 0xF6, 0xE9, 0xF2, 0x28, 0x1B, 0x59, 0x8B, 0x36, 0x94 };
	unsigned char szIV[16] = { 0xF0, 0xCE, 0xF9, 0x39, 0x2F, 0x94, 0xD1, 0xB8, 0x61, 0x12, 0x3B, 0xFE, 0x96, 0x87, 0x88, 0xE7 };
	//EVP_CIPHER_CTX_set_padding(pevpAESCBCCtx, 0); // By default padding is enabled
	EVP_CipherInit_ex(pevpAESCBCEncCtx, EVP_aes_128_cbc(), NULL, szKey, szIV, 1);
	//EVP_CIPHER_CTX_set_padding(pevpAESCBCCtx, 0); // By default padding is enabled
	//unsigned char szMsg[] = { "God is great all the time." };
	unsigned char szMsg[] =     { "God is good always & every time." };
	//unsigned char szMsg[] =   { "0123456789abcdef0123456789abedef" };

	cout << "Message:" << endl;
	cout << szMsg << endl;

	// Encryption
	unsigned char byCipher[48];
	int nCipherLen = 0;
	int nCipherTotLen = 0;
	EVP_CipherUpdate(pevpAESCBCEncCtx, byCipher, &nCipherLen, szMsg, strlen((const char*)szMsg));
	nCipherTotLen += nCipherLen;
	EVP_CipherFinal_ex(pevpAESCBCEncCtx, byCipher + nCipherTotLen, &nCipherLen);
	nCipherTotLen += nCipherLen;
	EVP_CIPHER_CTX_free(pevpAESCBCEncCtx);

	cout << "Encrypted message (padding enabled):" << endl;
	BIO_dump_fp(stdout, (const char*)byCipher, nCipherTotLen);


	// Decryption
	EVP_CIPHER_CTX* pEVPAESCBCDecCtx = NULL;
	pEVPAESCBCDecCtx = EVP_CIPHER_CTX_new();

	EVP_CipherInit_ex(pEVPAESCBCDecCtx, EVP_aes_128_cbc(), NULL, szKey, szIV, 0);
	//EVP_CIPHER_CTX_set_padding(pEVPAESCBCDecCtx, 0);
	unsigned char szCipherTemp[48];
	unsigned char szDMsg[48];
	int nDLen = 0;
	int nDTotLen = 0;
	//nCipherTotLen -= 0x10;
	bool nFound = false;
	//for(unsigned char szVal = 0; szVal < 255; szVal++)
	{
		EVP_CipherInit_ex(pEVPAESCBCDecCtx, EVP_aes_128_cbc(), NULL, szKey, szIV, 0);
		EVP_CIPHER_CTX_set_padding(pEVPAESCBCDecCtx, 0);
		memset(szDMsg, 0, 48);
		memcpy((void*)szCipherTemp, (const void*)byCipher, 48);
		nDLen = 0;
		nDTotLen = 0;
		//szCipherTemp[15] ^= (szVal ^ 0x01);
		//szCipherTemp[14] ^= (szVal ^ 0x02);
		//szCipherTemp[15] ^= ('f' ^ 0x02);
		if (1 == EVP_CipherUpdate(pEVPAESCBCDecCtx, szDMsg, &nDLen, szCipherTemp, nCipherTotLen))
		{
			//cout << (int)szVal << endl;
			nDTotLen += nDLen;
			if (1 == EVP_CipherFinal_ex(pEVPAESCBCDecCtx, szDMsg + nDTotLen, &nDLen))
			{
				nFound = true;
				//cout << szVal << endl;
				nDTotLen += nDLen;
				//break;
			}
		}
		EVP_CIPHER_CTX_reset(pEVPAESCBCDecCtx);
	}
	EVP_CIPHER_CTX_free(pEVPAESCBCDecCtx);

	if (nFound)
	{
		cout << "Decrypted message (padding disabled):" << endl;
		BIO_dump_fp(stdout, (const char*)szDMsg, nDTotLen);
	}
}
