/*
 * Source1.cpp
 *
 *  Created on: May 30, 2023
 *      Author: Ramnath
 */

#include <stdio.h>
#include <stdlib.h>
#include <curses.h>
#include <string.h>
#include <cmath>

#include <sys/select.h>
#include <termios.h>
#include <sys/ioctl.h>

#include <iostream>
#include <map>
#include <vector>
#include <chrono>
#include <atomic>
using namespace std;

#include <parallel/algorithm>
using namespace __gnu_parallel;

#include <openssl/err.h>

#include <openssl/bio.h>
#include <openssl/bioerr.h>

#include <openssl/evp.h>
#include <openssl/evperr.h>

#include <openssl/des.h>

class PRTimer
{
    chrono::steady_clock m_sc;
    chrono::steady_clock::time_point m_start;
public:
    //mpz_class m_x;
    vector<unsigned char> m_x;
    PRTimer()
    {
        m_start = m_sc.now();
    }

    //inline void DetectKeyBoard(const vector<unsigned char>& x)
    //{
    //    if (_kbhit())
    //    {
    //        wint_t wch = WEOF;
    //        m_x = x;
    //        wch = _getwch();
    //        if (wch != WEOF)
    //        {
    //            chrono::steady_clock::time_point end = m_sc.now();
    //            auto time_span = static_cast<chrono::duration<double>>(end - m_start);
    //           cout << "x = " << m_x.get_str() << " Operation took: " << time_span.count() << " seconds !!!" << endl;
    //        }
    //    }
    //}

    ~PRTimer()
    {
        chrono::steady_clock::time_point end = m_sc.now();
        auto time_span = static_cast<chrono::duration<double>>(end - m_start);
        //if (m_x != 0)
        //    cout << "x = " << m_x.get_str() << " Operation Finished. It took: " << time_span.count() << " seconds !!!" << endl;
        //else
            cout << "Operation Finished. It took: " << time_span.count() << " seconds !!!" << endl;
    }
};

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

// Increment 56 bit key staored in a 64 bit value. In every byte the most-siggnificant bit
// is a odd parity bit.
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

struct mpzComp
{
    bool operator()(const vector<unsigned char>& lhs, const pair<vector<unsigned char>, uint64_t>& rhs)
    {
        if (lhs < rhs.first)
            return true;
        return false;
    }
    bool operator()(const pair<vector<unsigned char>, uint64_t>& lhs, const vector<unsigned char>& rhs)
    {
        if (lhs.first < rhs)
            return true;
        return false;
    }
};

int main()
{
	// Decrypted value id obtained by encrypting plain text using 3DES ede3 ECB.
	// 3DES - 3 Data Encryption Standard
	// ede3 - Encrypt, Decrypt and Encrypt using 3 key.
	// ECB - Electronic Code book.
	// The cipher algritham in OpenSSL is EVP_des_ede3_ecb()
	// sz3DESEncData1 = E_K3(D_K2(E_K1(PlainText)))
	unsigned char szPlainText1[] = { "Hello" };
	unsigned char sz3DESEncData1[] = { 0xdf, 0x2b, 0xfb, 0x05, 0x16, 0x39, 0xdc, 0xa6 };
	int n3DESEncDataLen1 = 8;
	unsigned char szPlainText2[] = { "Over" };
	unsigned char sz3DESEncData2[] = { 0x02, 0x44, 0x23, 0xd8, 0x2b, 0x3c, 0x0d, 0x17 };
	int n3DESEncDataLen2 = 8;

	// There are the key that needs to be found using MITM Attack.
	//unsigned char szKey1[8] = { 0x57, 0xb0, 0xc4, 0x9b, 0x8c, 0x2f, 0x73, 0x2c };
	//unsigned char szKey2[8] = { 0x34, 0xef, 0xc1, 0x5b, 0x3d, 0xf7, 0x13, 0x20 };
	//unsigned char szKey3[8] = { 0x97, 0x92, 0xc7, 0x07, 0x92, 0x25, 0x4c, 0x0e };
	//unsigned char szKey4[24] = { 0x57, 0xb0, 0xc4, 0x9b, 0x8c, 0x2f, 0x73, 0x2c,
	//							0x34, 0xef, 0xc1, 0x5b, 0x3d, 0xf7, 0x13, 0x20,
	//							0x97, 0x92, 0xc7, 0x07, 0x92, 0x25, 0x4c, 0x0e };

	unsigned char szKey1[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char szKey2[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char szKey3[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char szKey4[24] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	// For Meet-In-The-Middle Attack the following should match
	// D_K3(sz3DESEncData1) = (D_K2(E_K1(PlainText1)))

    //typedef map<unsigned char[8], uint64_t> H2TABLE;
	//typedef map<vector<unsigned char>, uint64_t> H2TABLE;
	typedef vector<pair<vector<unsigned char>, uint64_t>> H2TABLE;
    H2TABLE h2t;

    // 1. Decrypt plain text and build the table for 2^56 possible keys..
	unsigned long long llMax1 = pow(2, 56);

	EVP_CIPHER_CTX* plhsDecryptCtx1 = NULL;
	plhsDecryptCtx1 = EVP_CIPHER_CTX_new();
	unsigned char szlhsDecBuff1[8];
	int nlhsDecLen1 = 0;
	int nlhsTotDecLen1 = 0;
	unsigned long long x2 = 0;
	{
		PRTimer prTimer;
        cout << "Building h table...! of size " << llMax1 << endl;

		do {
			EVP_DecryptInit(plhsDecryptCtx1, EVP_des_ecb(), szKey3, NULL);
			EVP_CIPHER_CTX_set_padding(plhsDecryptCtx1, 0);

			EVP_DecryptUpdate(plhsDecryptCtx1, szlhsDecBuff1, &nlhsDecLen1, sz3DESEncData1, n3DESEncDataLen1);
			ERR_print_errors_fp(stdout);
			nlhsTotDecLen1 = nlhsDecLen1;
			//cout << nlhsTotDecLen1 << endl;
			EVP_DecryptFinal(plhsDecryptCtx1, szlhsDecBuff1, &nlhsDecLen1);
			ERR_print_errors_fp(stdout);
			nlhsTotDecLen1 += nlhsDecLen1;
			//cout << nlhsTotDecLen1 << endl;

			// Build a table
			//BIO_dump_fp(stdout, (const char*)szlhsDecBuff1, nlhsTotDecLen1);
			vector<unsigned char> vlhsDecBuff1(begin(szlhsDecBuff1), end(szlhsDecBuff1));
			//h2t.insert(make_pair(vlhsDecBuff1, x2));
			h2t.push_back(make_pair(vlhsDecBuff1, x2));

			x2++; Incrememt56BitKey(szKey3);
		} while(x2 < llMax1);
        cout << "Finish building h table...! of size " << llMax1 << endl;
	}
	EVP_CIPHER_CTX_free(plhsDecryptCtx1);

	{
        PRTimer prTimer;
        cout << "Sorting h table...! of size " << llMax1 << endl;

        std::sort(h2t.begin(), h2t.end());

        cout << "Finish sorting h table...! of size " << llMax1 << endl;

	}

	// 2.Search the constructed table for evey possible 2^112 keys.
	EVP_CIPHER_CTX* prhsDecryptCtx3 = NULL;
	prhsDecryptCtx3 = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX* prhsDecryptCtx2 = NULL;
	prhsDecryptCtx2 = EVP_CIPHER_CTX_new();
	int nPlainTextLen1 = strlen((const char*)szPlainText1);
	nPlainTextLen1++; // Include NULL
	int nComp = 1;

	//cancellation_token_source cts;

	//cout << "nPlainTextLen1 " << nPlainTextLen1 << endl;
	//nPlainTextLen1 += EVP_CIPHER_CTX_block_size(prhsDecryptCtx3) - nPlainTextLen1 % EVP_CIPHER_CTX_block_size(prhsDecryptCtx3);
	//H2TABLE::iterator itrx2 = h2t.end();
	// The following search can be placed in a hread for efficient searching.
	{
        PRTimer prTimer;
        cout << "Search h table using g...!" << endl;

        uint64_t j = 0;
		for (; j < llMax1; j++, Incrememt56BitKey(szKey1)) {

			EVP_EncryptInit(prhsDecryptCtx3, EVP_des_ecb(), szKey1, NULL);
			//EVP_CIPHER_CTX_set_padding(prhsDecryptCtx3, 0); // No need as it a plain text
			unsigned char szrhsDecBuff3[8];
			int nrhsDecLen3 = 0;
			int nrhsTotDecLen3 = 0;
			EVP_EncryptUpdate(prhsDecryptCtx3, szrhsDecBuff3, &nrhsDecLen3, szPlainText1, nPlainTextLen1);
			ERR_print_errors_fp(stdout);
			nrhsTotDecLen3 = nrhsDecLen3;
			//cout << nrhsTotDecLen3 << endl;
			EVP_EncryptFinal(prhsDecryptCtx3, szrhsDecBuff3, &nrhsDecLen3);
			ERR_print_errors_fp(stdout);
			nrhsTotDecLen3 += nrhsDecLen3;
			//cout << nrhsTotDecLen3 << endl;
			//BIO_dump_fp(stdout, (const char*)szrhsDecBuff3, nrhsTotDecLen3);
			uint64_t k = 0;
			for(k = 0; k < llMax1; k++, Incrememt56BitKey(szKey2)) {

				// 3.
				EVP_DecryptInit(prhsDecryptCtx2, EVP_des_ecb(), szKey2, NULL);
				EVP_CIPHER_CTX_set_padding(prhsDecryptCtx2, 0);
				unsigned char szrhsDecBuff2[8];
				int nrhsDecLen2 = 0;
				int nrhsTotDecLen2 = 0;
				EVP_DecryptUpdate(prhsDecryptCtx2, szrhsDecBuff2, &nrhsDecLen2, szrhsDecBuff3, nrhsTotDecLen3);
				ERR_print_errors_fp(stdout);
				nrhsTotDecLen2 = nrhsDecLen2;
				//cout << nrhsTotDecLen2 << endl;
				EVP_DecryptFinal(prhsDecryptCtx2, szrhsDecBuff2, &nrhsDecLen2);
				ERR_print_errors_fp(stdout);
				nrhsTotDecLen2 += nrhsDecLen2;
				//cout << nrhsTotDecLen2 << endl;

				// Check everu valy in the table
				//BIO_dump_fp(stdout, (const char*)szrhsDecBuff2, nrhsTotDecLen2);

				//if ((nlhsTotDecLen1 == nrhsTotDecLen2) && (0 == (nComp = memcmp(szlhsDecBuff1, szrhsDecBuff2, nrhsTotDecLen2))))
				//{
				//	break;
				//}
				//cout << nComp << endl;

				vector<unsigned char> vrhsDecBuff2(begin(szrhsDecBuff2), end(szrhsDecBuff2));
				//H2TABLE::iterator itrx2Tmp;
				//itrx2Tmp = h2t.find(vrhsDecBuff2);
				//if (itrx2Tmp != h2t.end()) {
				//	break;
				if (std::binary_search(h2t.begin(), h2t.end(), vrhsDecBuff2, mpzComp()))
				{
					nComp = 0;
					break;
				}
			}
			// reak if the match is found.
			if (k < llMax1) break;
		}
	}
	EVP_CIPHER_CTX_free(prhsDecryptCtx3);
	EVP_CIPHER_CTX_free(prhsDecryptCtx2);

		// Test another pair of data and encrypted text and check whether the key is correct or not.
	if (0 == nComp) {
		memcpy(szKey4, szKey1, 8); memcpy(szKey4 + 8, szKey2, 8); memcpy(szKey4 + 16, szKey3, 8);
		EVP_CIPHER_CTX* pEVOCIPCTX4 = NULL;
		pEVOCIPCTX4 = EVP_CIPHER_CTX_new();
		EVP_DecryptInit(pEVOCIPCTX4, EVP_des_ede3_ecb(), szKey4, NULL);
		unsigned char szTestBuff[64];
		int nTestBuffLen = 0;
		int nTotTestBuffLen = 0;
		EVP_DecryptUpdate(pEVOCIPCTX4, szTestBuff, &nTestBuffLen, sz3DESEncData2, n3DESEncDataLen2);
		nTotTestBuffLen = nTestBuffLen;
		//cout << nTotTestBuffLen << endl;
		EVP_DecryptFinal(pEVOCIPCTX4, szTestBuff + nTotTestBuffLen, &nTestBuffLen);
		//ERR_print_errors_fp(stdout);
		nTotTestBuffLen += nTestBuffLen;
		//cout << nTotTestBuffLen << endl;
		if (0 == strcmp((const char*)szTestBuff, (const char*)szPlainText2)) {
			cout << "The Key is :" << endl;
			BIO_dump_fp(stdout, (const char*)szKey4, 24);
		}

		EVP_CIPHER_CTX_free(pEVOCIPCTX4);
	}

	return 0;
}
