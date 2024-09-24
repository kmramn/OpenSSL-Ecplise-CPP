/*
 * Source1.cpp
 *
 *  Created on: May 21, 2023
 *      Author: Ramnath
 */

#include <stdio.h>
#include <unistd.h>

#include <iostream>
using namespace std;

#include <gmp.h>
#include <gmpxx.h>

#include <openssl/err.h>

#include <openssl/bio.h>
#include <openssl/bioerr.h>

#include <openssl/evp.h>
#include <openssl/evperr.h>

#include <openssl/des.h>

unsigned char Bits56CarryAfterIncrement(unsigned char szKey)
{
	// Check if all bit is 1 and the carry is 1 after increment
	return (( (szKey) & 1) & ((szKey >> 1) & 1) & ((szKey >> 2) & 1) & ((szKey >> 3) & 1) &
			((szKey >> 4) & 1) & ((szKey >> 5) & 1) & ((szKey >> 6) & 1)
			);
}

void SetOddParity(unsigned char &szKey)
{
	szKey &= 127;
	szKey |= (( ((szKey) & 1) ^ ((szKey >> 1) & 1) ^ ((szKey >> 2) & 1) ^
			((szKey >> 3) & 1) ^ ((szKey >> 4) & 1) ^ ((szKey >> 5) & 1) ^
			((szKey >> 6) & 1) ^ 1) << 7);
}

void Incrememt56BitKey(unsigned char szKeys[8])
{
	unsigned char szCarry0 = Bits56CarryAfterIncrement(szKeys[7]++);
	SetOddParity(szKeys[7]);
	unsigned char szCarry1 = Bits56CarryAfterIncrement(szKeys[6]) & szCarry0;
	szKeys[6] += szCarry0;
	SetOddParity(szKeys[6]);
	unsigned char szCarry2 = Bits56CarryAfterIncrement(szKeys[5]) & szCarry1;
	szKeys[5] += szCarry1;
	SetOddParity(szKeys[5]);
	unsigned char szCarry3 = Bits56CarryAfterIncrement(szKeys[4]) & szCarry2;
	szKeys[4] += szCarry2;
	SetOddParity(szKeys[4]);
	unsigned char szCarry4 = Bits56CarryAfterIncrement(szKeys[3]) & szCarry3;
	szKeys[3] += szCarry3;
	SetOddParity(szKeys[3]);
	unsigned char szCarry5 = Bits56CarryAfterIncrement(szKeys[2]) & szCarry4;
	szKeys[2] += szCarry4;
	SetOddParity(szKeys[2]);
	unsigned char szCarry6 = Bits56CarryAfterIncrement(szKeys[1]) & szCarry5;
	szKeys[1] += szCarry5;
	SetOddParity(szKeys[1]);
	szKeys[0] += szCarry6;
	SetOddParity(szKeys[0]);
}

int main()
{
	// k1:10110010110000000110011011010010010101000010000010010111 (B2C066D2542097)
	// k2:10000110000111000000110000111100111000011100110011110001 (861C0C3CE1CCF1)
	// k3:10100010010011101011001110010001001100000110111000111011 (A24EB391306E3B)
	//unsigned char szk1[8] = { 0xB2, 0xC0, 0x66, 0xD2, 0x54, 0x20, 0x97 };
	//unsigned char szk2[] = { 0x86, 0x1C, 0x0C, 0x3C, 0xE1, 0xCC, 0xF1 };
	//unsigned char szk3[] = { 0xA2, 0x4E, 0xB3, 0x91, 0x30, 0x6E, 0x3B };
	/*for (int i = 0; i < 10000000; i++)
	{
		Incrememt56BitKey(szk1);
		BIO_dump_fp(stdout, (const char*)szk1, 8);
	}*/

	unsigned char szk[] = { 0x57, 0xb0, 0xc4, 0x9b, 0x8c, 0x2f, 0x73, 0x2c, 0x34, 0xef, 0xc1, 0x5b, 0x3d, 0xf7, 0x13, 0x20, 0x97, 0x92, 0xc7, 0x07, 0x92, 0x25, 0x4c, 0x0e };

	// 3DES Encryption
	EVP_CIPHER_CTX* pCIPHERCTX = NULL;
	pCIPHERCTX = EVP_CIPHER_CTX_new();
	//EVP_EncryptInit_ex(pCIPHERCTX, EVP_des_ede3(), NULL, szk, NULL);
	EVP_EncryptInit(pCIPHERCTX, EVP_des_ede3_ecb(), szk, NULL);
	//EVP_CIPHER_CTX_set_padding(pCIPHERCTX, 0);
	//unsigned char szBuff[] = "Praise ye the Lord. Praise ye the Lord. Amen";
	unsigned char szBuff[] = "Over";
	int nBufLen = strlen((const char*)szBuff) + 1; // Include NULL
	cout << "Buff len:" << nBufLen << endl;

	int nEncLen = 0;
	//EVP_EncryptUpdate(pCIPHERCTX, NULL, &nEncLen, szBuff, nBufLen);
	//cout << "EncLen :" << nEncLen << endl;

	//cipher_block_size;
	int nBlockSize = EVP_CIPHER_CTX_block_size(pCIPHERCTX);
	cout << "BlockLen " << nBlockSize << endl;
	nEncLen = nBufLen + nBlockSize - 1;
	cout << "Pre Encrypted Len : " << nEncLen << endl;

	unsigned char* szEncBuff = NULL;
	szEncBuff = (unsigned char*)OPENSSL_malloc(nEncLen);
	cout << EVP_EncryptUpdate(pCIPHERCTX, szEncBuff, &nEncLen, szBuff, nBufLen) << endl;
	ERR_print_errors_fp(stdout);
	cout << "Encrypted Len : " << nEncLen << endl;
	BIO_dump_fp(stdout, (const char*)szEncBuff, nEncLen);

	int nTotEncLen = nEncLen;
	nEncLen = 0;
	EVP_EncryptFinal(pCIPHERCTX, szEncBuff + nTotEncLen, &nEncLen);
	cout << "Final Enc len : " << nEncLen << endl;
	nTotEncLen += nEncLen;
	cout << "Tot Enc len : " << nTotEncLen << endl;
	BIO_dump_fp(stdout, (const char*)szEncBuff, nTotEncLen);
	//cout << EVP_CIPHER_CTX_key_length(pCIPHERCTX) << endl;
	//unsigned char szKey[24];
	//EVP_CIPHER_CTX_rand_key(pCIPHERCTX, szKey);
	//BIO_dump_fp(stdout, (const char *)szKey, 24);
	//ERR_print_errors_fp(stdout);
	EVP_CIPHER_CTX_free(pCIPHERCTX);

	// 3DES Decryption
	EVP_CIPHER_CTX* pDecryptCtx = NULL;
	pDecryptCtx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit(pDecryptCtx, EVP_des_ede3(), szk, NULL);
	//EVP_CIPHER_CTX_set_padding(pDecryptCtx, 0);
	unsigned char szDecryptBuff[nTotEncLen];
	memset(szDecryptBuff, 0, sizeof(szDecryptBuff));
	int nDecLen = 8;
	BIO_dump_fp(stdout, (const char*)szEncBuff, nTotEncLen);
	EVP_DecryptUpdate(pDecryptCtx, szDecryptBuff, &nDecLen, szEncBuff, nTotEncLen);
	cout << "nDecLen " << nDecLen << endl;
	int nTotDecLen = nDecLen;
	EVP_DecryptFinal(pDecryptCtx, szDecryptBuff + nTotDecLen, &nDecLen);
	cout << "nDecLen " << nDecLen << endl;
	nTotDecLen += nDecLen;
	cout << "nTotDecLen " << nTotDecLen << endl;
	cout << "szDecryptBuff " << szDecryptBuff << endl;
	EVP_CIPHER_CTX_free(pDecryptCtx);

	// 1DES
	EVP_CIPHER_CTX* pEVPCipherCtx1 = NULL;
	pEVPCipherCtx1 = EVP_CIPHER_CTX_new();
	EVP_DecryptInit(pEVPCipherCtx1, EVP_des_ecb(), szk + 16, NULL);
	EVP_CIPHER_CTX_set_padding(pEVPCipherCtx1, 0);
	unsigned char szEncBuff1[nTotEncLen];
	int nEncLen1 = 0;
	int nTotDecLen1 = 0;
	BIO_dump_fp(stdout, (const char*)szEncBuff, nTotEncLen);
	cout << EVP_DecryptUpdate(pEVPCipherCtx1, szEncBuff1, &nEncLen1, szEncBuff, nTotEncLen) << endl;
	nTotDecLen1 = nEncLen1;
	cout << "nEncLen1 " << nEncLen1 << endl;
	cout << EVP_DecryptFinal(pEVPCipherCtx1, szEncBuff1 + nTotDecLen1, &nEncLen1) << endl;
	ERR_print_errors_fp(stdout);
	cout << "nEncLen1 " << nEncLen1 << endl;
	nTotDecLen1 += nEncLen1;
	cout << "nTotDecLen1 " << nTotDecLen1 << endl;
	EVP_CIPHER_CTX_free(pEVPCipherCtx1);
	BIO_dump_fp(stdout, (const char*)szEncBuff1, nTotDecLen1);

	// 2DES
	EVP_CIPHER_CTX* pEVPCipherCtx2 = NULL;
	pEVPCipherCtx2 = EVP_CIPHER_CTX_new();
	EVP_EncryptInit(pEVPCipherCtx2, EVP_des_ecb(), szk + 8, NULL);
	EVP_CIPHER_CTX_set_padding(pEVPCipherCtx2, 0);
	unsigned char szEncBuff2[nTotDecLen1 + EVP_CIPHER_CTX_block_size(pEVPCipherCtx2)];
	int nEncLen2 = 0;
	int nTotDecLen2 = 0;
	cout << EVP_EncryptUpdate(pEVPCipherCtx2, szEncBuff2, &nEncLen2, szEncBuff1, nTotDecLen1) << endl;
	nTotDecLen2 = nEncLen2;
	cout << "nEncLen2 " << nEncLen2 << endl;
	cout << EVP_EncryptFinal(pEVPCipherCtx2, szEncBuff2 + nTotDecLen2, &nEncLen2) << endl;
	cout << "nEncLen2 " << nEncLen2 << endl;
	nTotDecLen2 += nEncLen2;
	cout << "nTotDecLen2 " << nTotDecLen2 << endl;
	EVP_CIPHER_CTX_free(pEVPCipherCtx2);
	BIO_dump_fp(stdout, (const char*)szEncBuff2, nTotDecLen2);

	// 3 DES
	EVP_CIPHER_CTX* pEVPCipherCtx3 = NULL;
	pEVPCipherCtx3 = EVP_CIPHER_CTX_new();
	EVP_DecryptInit(pEVPCipherCtx3, EVP_des_ecb(), szk + 0, NULL);
	//EVP_CIPHER_CTX_set_padding(pEVPCipherCtx3, 0);
	unsigned char szEncBuff3[nTotDecLen2];
	memset(szEncBuff3, 0, nTotDecLen);
	int nEncLen3 = 0;
	int nTotDecLen3 = 0;
	cout << EVP_DecryptUpdate(pEVPCipherCtx3, szEncBuff3, &nEncLen3, szEncBuff2, nTotDecLen2) << endl;
	nTotDecLen3 = nEncLen3;
	cout << "nEncLen3 " << nEncLen3 << endl;
	cout << EVP_DecryptFinal(pEVPCipherCtx3, szEncBuff3 + nTotDecLen3, &nEncLen3) << endl;
	cout << "nEncLen3 " << nEncLen3 << endl;
	nTotDecLen3 += nEncLen3;
	EVP_CIPHER_CTX_free(pEVPCipherCtx3);
	cout << "nTotDecLen3 " << nTotDecLen3 << endl;
	cout << "szEncBuff3 " << szEncBuff3 << endl;
	BIO_dump_fp(stdout, (const char*)szEncBuff3, nTotDecLen3);

	OPENSSL_free(szEncBuff);

	EVP_MAC_
	return 0;
}
