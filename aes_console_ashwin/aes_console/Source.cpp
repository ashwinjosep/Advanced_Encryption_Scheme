// AES_Console.cpp : Defines the entry point for the console application.

#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <vector>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <bcrypt.h>
#include <bitset>
#include <iomanip>
#include <cmath>

#pragma comment(lib, "Bcrypt")


using namespace std;

// Structure for state type
struct state
{
	std::byte stateByte[4][4];
};

//Structure for word type
struct word
{
	std::byte byteWord[4];
};

class AES {

	// IV variable
	state IV;

	//Key Value
	word expandedKey[60];

	// Length Parameters
	int Nk;
	int Nb;
	int Nr;

public:

	void setParameters(int option, string keyFileString)
	{
		Nb = 4;
		if (option == 3)
		{
			// AES256
			Nk = 8;
			Nr = 14;
		}
		else if (option == 2)
		{
			// AES192
			Nk = 6;
			Nr = 12;
		}
		else
		{
			// AES256
			Nk = 4;
			Nr = 10;
		}

		setKey(keyFileString);
	}

	// message encryption method, at the multiple block level
	vector<std::byte> encrypt(vector<struct state*> input)
	{
		//output vector of encrypted blocks
		vector<struct state*> output;

		output.push_back(new state);
		//Generate IV randomly, and set it as the first block
		generateIV();
		*(output.back()) = IV;

		//for each input block, create an encrypted output block in CBC mode
		for (unsigned int i = 0; i < input.size(); i++)
		{
			output.push_back(new state);
			*(output.back()) = blockEncrypt(xorBlock(output[i], input[i]));
		}

		vector<std::byte> outputMessage;
		//copy over the bytes for all blocks
		for (unsigned int i = 0; i < output.size(); i++)
		{
			for (int j = 0; j < 4; j++)
			{
				for (int k = 0; k < 4; k++)
				{
					outputMessage.push_back(output[i]->stateByte[k][j]);
				}
			}
		}

		//clean up dynamic memory
		for (unsigned int i = 0; i < output.size(); i++)
		{
			delete output[i];
		}

		return outputMessage;
	}

	// message decryption method, at the multiple block level
	vector<std::byte> decrypt(vector<struct state*> input)
	{
		//output vector of decrypted blocks
		vector<struct state*> output;
		//for each input block, xor with the previous block
		//IV is the first block, so start from i=1
		for (unsigned int i = 1; i < input.size(); i++)
		{
			output.push_back(new state);
			*(output.back()) = xorBlock(&blockDecrypt(*input[i]), input[i - 1]);
		}
		vector<std::byte> outputMessage;
		//copy over the bytes for all but the padding block
		for (unsigned int i = 0; i < output.size() - 1; i++)
		{
			for (int j = 0; j < 4; j++)
			{
				for (int k = 0; k < 4; k++)
				{
					outputMessage.push_back(output[i]->stateByte[k][j]);
				}
			}
		}
		//I wasn't able to remove padding in constant time
		std::byte paddingValue = output.back()->stateByte[3][3];
		int integrity = (int)paddingValue;
		boolean integrityCheck = false;

		//start from the end, and check each byte for each column,
		for (int i = 3; i >= 0; i--)
		{
			//row by row
			for (int j = 3; j >= 0; j--)
			{
				if (integrity == 0)
				{
					outputMessage.insert(outputMessage.begin() + ((output.size() - 1) * 16), output.back()->stateByte[j][i]);
					integrityCheck = true;
				}
				else if (output.back()->stateByte[j][i] == paddingValue)
				{
					integrity = integrity - 1;
				}
			}
		}
		if (!integrityCheck)
		{
			//in this case, there was a padding error, and the only way to completely prevent padding oracle is to authenticate before even decrypting

			//can only try to minimize the difference in execution time caused by realizing the padding is incorrect
			//with correct padding, there would be from 0 to 15 insertions to the beginning of the outputMessage, but there were none in this case

		}

		//clean up dynamic memory
		for (unsigned int i = 0; i < output.size(); i++)
		{
			delete output[i];
		}

		return outputMessage;
	}

private:

	void setKey(string keyFileString)
	{
		//open the key input file
		ifstream keyFile;
		keyFile.open(keyFileString, ios::binary | ios::in);

		int i = 0;
		int j = 0;

		//TODO, handle >128 bit keys, new struct?
		while (!keyFile.eof())
		{
			for (i = 0; i < Nk; i++)
			{
				for (j = 0; j < 4; j++)
				{
					keyFile.read((char*)(&(expandedKey[i].byteWord[j])), 1);
				}
			}
		}

		keyFile.close();

		//If key length is less than required generate random
		if (i < Nk || j < 4)
		{
			std::stringstream stream;
			int tempWord = 0;
			for (; i < Nk; i++)
			{
				for (j = 0; j < 4; j++)
				{
					do
					{
						tempWord = generateRandom();
					} while (tempWord == 0);
					stream << std::hex << tempWord;
					expandedKey[i].byteWord[j] = std::byte(tempWord);
				}
			}
		}

		// Perform Key Expansion
		keyExpansion();
	}

	//Random Number Generator
	int generateRandom()
	{
		BCRYPT_ALG_HANDLE Prov;
		int Buffer = 0;
		if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&Prov, BCRYPT_RNG_ALGORITHM, NULL, 0)))
		{
			Buffer = 0;
		}
		if (!BCRYPT_SUCCESS(BCryptGenRandom(Prov, (PUCHAR)(&Buffer), sizeof(Buffer), 0)))
		{
			Buffer = 0;
		}
		BCryptCloseAlgorithmProvider(Prov, 0);
		return Buffer;
	}

	// Random IV Generator 
	void generateIV()
	{

		std::stringstream stream;
		int tempWord = 0;
		for (int i = 0; i < 4; i++)
		{
			for (int j = 0; j < 4; j++)
			{
				do
				{
					tempWord = generateRandom();
				} while (tempWord == 0);
				stream << std::hex << tempWord;
				IV.stateByte[i][j] = std::byte(tempWord);
			}
		}
	}

	//use this to construct XNOR along with the ^ operator
	//should be constant time since one condition is always checked, and there is one operation per branch
	std::byte NOTOP(std::byte v1)
	{
		if (v1 == std::byte{ 0x1 })
		{
			return std::byte{ 0x0 };
		}
		else
		{
			return std::byte{ 0x1 };
		}
	}

	//bitslicing implementation of AES Sbox, using Joan Boyar and Rene Peralta's circuit, designed in https://eprint.iacr.org/2011/332.pdf
	std::byte SubBytes(std::byte in)
	{
		//u0 is msb, u7 is lsb
		//get rid of the other bits
		std::byte u0 = in >> 7;
		std::byte u1 = (in << 1) >> 7;
		std::byte u2 = (in << 2) >> 7;
		std::byte u3 = (in << 3) >> 7;
		std::byte u4 = (in << 4) >> 7;
		std::byte u5 = (in << 5) >> 7;
		std::byte u6 = (in << 6) >> 7;
		std::byte u7 = (in << 7) >> 7;

		//intermediate values, top linear transformation
		std::byte t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14, t15, t16, t17, t18, t19, t20, t21, t22, t23, t24, t25, t26, t27;
		//perform the top linear transform
		t1 = u0 ^ u3;
		t2 = u0 ^ u5;
		t3 = u0 ^ u6;
		t4 = u3 ^ u5;
		t5 = u4 ^ u6;
		t6 = t1 ^ t5;
		t7 = u1 ^ u2;

		t8 = u7 ^ t6;
		t9 = u7 ^ t7;
		t10 = t6 ^ t7;
		t11 = u1 ^ u5;
		t12 = u2 ^ u5;
		t13 = t3 ^ t4;
		t14 = t6 ^ t11;

		t15 = t5 ^ t11;
		t16 = t5 ^ t12;
		t17 = t9 ^ t16;
		t18 = u3 ^ u7;
		t19 = t7 ^ t18;
		t20 = t1 ^ t19;
		t21 = u6 ^ u7;

		t22 = t7 ^ t21;
		t23 = t2 ^ t22;
		t24 = t2 ^ t10;
		t25 = t20 ^ t17;
		t26 = t3 ^ t16;
		t27 = t1 ^ t12;

		
		//shared middle values, forward direction
		std::byte m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22, m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40, m41, m42, m43, m44, m45, m46, m47, m48, m49, m50, m51, m52, m53, m54, m55, m56, m57, m58, m59, m60, m61, m62, m63;

		//perform the shared portion, with d=u7
		m1 = t13 & t6;
		m2 = t23 & t8;
		m3 = t14 ^ m1;
		m4 = t19 & u7;
		m5 = m4 ^ m1;
		m6 = t3 & t16;
		m7 = t22 & t9;
		m8 = t26 ^ m6;
		m9 = t20 & t17;
		m10 = m9 ^ m6;
		m11 = t1 & t15;
		m12 = t4 & t27;
		m13 = m12 ^ m11;
		m14 = t2 & t10;
		m15 = m14 ^ m11;
		m16 = m3 ^ m2;

		m17 = m5 ^ t24;
		m18 = m8 ^ m7;
		m19 = m10 ^ m15;
		m20 = m16 ^ m13;
		m21 = m17 ^ m15;
		m22 = m18 ^ m13;
		m23 = m19 ^ t25;
		m24 = m22 ^ m23;
		m25 = m22 & m20;
		m26 = m21 ^ m25;
		m27 = m20 ^ m21;
		m28 = m23 ^ m25;
		m29 = m28 & m27;
		m30 = m26 & m24;
		m31 = m20 & m23;
		m32 = m27 & m31;

		m33 = m27 ^ m25;
		m34 = m21 & m22;
		m35 = m24 & m34;
		m36 = m24 ^ m25;
		m37 = m21 ^ m29;
		m38 = m32 ^ m33;
		m39 = m23 ^ m30;
		m40 = m35 ^ m36;
		m41 = m38 ^ m40;
		m42 = m37 ^ m39;
		m43 = m37 ^ m38;
		m44 = m39 ^ m40;
		m45 = m42 ^ m41;
		m46 = m44 & t6;
		m47 = m40 & t8;
		m48 = m39 & u7;

		m49 = m43 & t16;
		m50 = m38 & t9;
		m51 = m37 & t17;
		m52 = m42 & t15;
		m53 = m45 & t27;
		m54 = m41 & t10;
		m55 = m44 & t13;
		m56 = m40 & t23;
		m57 = m39 & t19;
		m58 = m43 & t3;
		m59 = m38 & t22;
		m60 = m37 & t20;
		m61 = m42 & t1;
		m62 = m45 & t4;
		m63 = m41 & t2;

		//bottom linear transformation variables
		std::byte l0, l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16, l17, l18, l19, l20, l21, l22, l23, l24, l25, l26, l27, l28, l29;
		//output variables of the sbox and bottom linear transform
		std::byte s0, s1, s2, s3, s4, s5, s6, s7;

		l0 = m61 ^ m62;
		l1 = m50 ^ m56;
		l2 = m46 ^ m48;
		l3 = m47 ^ m55;
		l4 = m54 ^ m58;
		l5 = m49 ^ m61;
		l6 = m62 ^ l5;
		l7 = m46 ^ l3;
		l8 = m51 ^ m59;
		l9 = m52 ^ m53;
		l10 = m53 ^ l4;
		l11 = m60 ^ l2;
		l12 = m48 ^ m51;
		l13 = m50 ^ l0;
		l14 = m52 ^ m61;
		l15 = m55 ^ l1;
		l16 = m56 ^ l0;
		l17 = m57 ^ l1;
		l18 = m58 ^ l8;
		l19 = m63 ^ l4;
		l20 = l0 ^ l1;
		l21 = l1 ^ l7;
		l22 = l3 ^ l12;
		l23 = l18 ^ l2;
		l24 = l15 ^ l9;
		l25 = l6 ^ l10;
		l26 = l7 ^ l9;
		l27 = l8 ^ l10;
		l28 = l11 ^ l14;
		l29 = l11 ^ l17;

		s0 = l6 ^ l24;
		s1 = (NOTOP(l16 ^ l26));
		//s1 = s1 >> 7;
		s2 = (NOTOP(l19 ^ l28));
		//s2 = s2 >> 7;
		s3 = l6 ^ l21;
		s4 = l20 ^ l22;
		s5 = l25 ^ l29;
		s6 = (NOTOP(l13 ^ l27));
		//s6 = s6 >> 7;
		s7 = (NOTOP(l6 ^ l23));
		//s6 = s6 >> 7;

		s0 = s0 << 7;
		s1 = s1 << 6;
		s2 = s2 << 5;
		s3 = s3 << 4;
		s4 = s4 << 3;
		s5 = s5 << 2;
		s6 = s6 << 1;

		return s0 ^ s1 ^ s2 ^ s3 ^ s4 ^ s5 ^ s6 ^ s7;
	}

	//bitslicing implementation of inverse AES Sbox, using Joan Boyar and Rene Peralta's circuit, designed in https://eprint.iacr.org/2011/332.pdf
	std::byte InvSubBytes(std::byte in)
	{
		//u0 is msb, u7 is lsb
		//get rid of the other bits
		std::byte u0 = in >> 7;
		std::byte u1 = (in << 1) >> 7;
		std::byte u2 = (in << 2) >> 7;
		std::byte u3 = (in << 3) >> 7;
		std::byte u4 = (in << 4) >> 7;
		std::byte u5 = (in << 5) >> 7;
		std::byte u6 = (in << 6) >> 7;
		std::byte u7 = (in << 7) >> 7;

		//intermediate values, top linear transformation
		std::byte t1, t2, t3, t4, t6, t8, t9, t10, t13, t14, t15, t16, t17, t19, t20, t22, t23, t24, t25, t26, t27;
		//some different intermediate variables for the inverse
		std::byte r5, r13, r17, r18, r19, y5;
		//compute the top linear transform in reverse
		t23 = u0 ^ u3;
		t22 = NOTOP(u1 ^ u3);
		t2 = NOTOP(u0 ^ u1);
		t1 = u3 ^ u4;
		t24 = NOTOP(u4 ^ u7);
		r5 = u6 ^ u7;
		t8 = NOTOP(u1 ^ t23);

		t19 = t22 ^ r5;
		t9 = NOTOP(u7 ^ t1);
		t10 = t2 ^ t24;
		t13 = t2 ^ r5;
		t3 = t1 ^ r5;
		t25 = NOTOP(u2 ^ t1);
		r13 = u1 ^ u6;

		t17 = NOTOP(u2 ^ t19);
		t20 = t24 ^ r13;
		t4 = u4 ^ t8;
		r17 = NOTOP(u2 ^ u5);
		r18 = NOTOP(u5 ^ u6);
		r19 = NOTOP(u2 ^ u4);
		y5 = u0 ^ r17;

		t6 = t22 ^ r17;
		t16 = r13 ^ r19;
		t27 = t1 ^ r18;
		t15 = t10 ^ t27;
		t14 = t10 ^ r18;
		t26 = t3 ^ t16;

		//shared middle values
		std::byte m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22, m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40, m41, m42, m43, m44, m45, m46, m47, m48, m49, m50, m51, m52, m53, m54, m55, m56, m57, m58, m59, m60, m61, m62, m63;

		//perform the shared portion, with d=y5
		m1 = t13 & t6;
		m2 = t23 & t8;
		m3 = t14 ^ m1;
		m4 = t19 & y5;
		m5 = m4 ^ m1;
		m6 = t3 & t16;
		m7 = t22 & t9;
		m8 = t26 ^ m6;
		m9 = t20 & t17;
		m10 = m9 ^ m6;
		m11 = t1 & t15;
		m12 = t4 & t27;
		m13 = m12 ^ m11;
		m14 = t2 & t10;
		m15 = m14 ^ m11;
		m16 = m3 ^ m2;

		m17 = m5 ^ t24;
		m18 = m8 ^ m7;
		m19 = m10 ^ m15;
		m20 = m16 ^ m13;
		m21 = m17 ^ m15;
		m22 = m18 ^ m13;
		m23 = m19 ^ t25;
		m24 = m22 ^ m23;
		m25 = m22 & m20;
		m26 = m21 ^ m25;
		m27 = m20 ^ m21;
		m28 = m23 ^ m25;
		m29 = m28 & m27;
		m30 = m26 & m24;
		m31 = m20 & m23;
		m32 = m27 & m31;

		m33 = m27 ^ m25;
		m34 = m21 & m22;
		m35 = m24 & m34;
		m36 = m24 ^ m25;
		m37 = m21 ^ m29;
		m38 = m32 ^ m33;
		m39 = m23 ^ m30;
		m40 = m35 ^ m36;
		m41 = m38 ^ m40;
		m42 = m37 ^ m39;
		m43 = m37 ^ m38;
		m44 = m39 ^ m40;
		m45 = m42 ^ m41;
		m46 = m44 & t6;
		m47 = m40 & t8;
		m48 = m39 & y5;

		m49 = m43 & t16;
		m50 = m38 & t9;
		m51 = m37 & t17;
		m52 = m42 & t15;
		m53 = m45 & t27;
		m54 = m41 & t10;
		m55 = m44 & t13;
		m56 = m40 & t23;
		m57 = m39 & t19;
		m58 = m43 & t3;
		m59 = m38 & t22;
		m60 = m37 & t20;
		m61 = m42 & t1;
		m62 = m45 & t4;
		m63 = m41 & t2;

		//intermediate variables for the bottom linear transformation, in the reverse direction
		std::byte p0, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10, p11, p12, p13, p14, p15, p16, p17, p18, p19, p20, p22, p23, p24, p25, p26, p27, p28, p29;
		//output variables
		std::byte w0, w1, w2, w3, w4, w5, w6, w7;

		p0 = m52 ^ m61;
		p1 = m58 ^ m59;
		p2 = m54 ^ m62;
		p3 = m47 ^ m50;
		p4 = m48 ^ m56;
		p5 = m46 ^ m51;
		p6 = m49 ^ m60;
		p7 = p0 ^ p1;
		p8 = m50 ^ m53;
		p9 = m55 ^ m63;

		p10 = m57 ^ p4;
		p11 = p0 ^ p3;
		p12 = m46 ^ m48;
		p13 = m49 ^ m51;
		p14 = m49 ^ m62;
		p15 = m54 ^ m59;
		p16 = m57 ^ m61;
		p17 = m58 ^ p2;
		p18 = m63 ^ p5;
		p19 = p2 ^ p3;

		p20 = p4 ^ p6;
		p22 = p2 ^ p7;
		p23 = p7 ^ p8;
		p24 = p5 ^ p7;
		p25 = p6 ^ p10;
		p26 = p9 ^ p11;
		p27 = p10 ^ p18;
		p28 = p11 ^ p25;
		p29 = p15 ^ p20;
		
		w0 = p13 ^ p22;
		w1 = p26 ^ p29;
		w2 = p17 ^ p28;
		w3 = p12 ^ p22;
		w4 = p23 ^ p27;
		w5 = p19 ^ p24;
		w6 = p14 ^ p23;
		w7 = p9 ^ p16;

		//rearrange the bits back to their locations
		w0 = w0 << 7;
		w1 = w1 << 6;
		w2 = w2 << 5;
		w3 = w3 << 4;
		w4 = w4 << 3;
		w5 = w5 << 2;
		w6 = w6 << 1;

		//combine the bits into the byte value
		return w0 ^ w1 ^ w2 ^ w3 ^ w4 ^ w5 ^ w6 ^ w7;
	}

	//S-Box substitution for all bytes of the byteword
	word SubWord(struct word input)
	{
		word result;
		for (int i = 0; i < 4; i++)
		{
			result.byteWord[i] = SubBytes(input.byteWord[i]);
		}
		return result;
	}

	// xors 2 state matrices
	struct state xorBlock(struct state* s1, struct state* s2)
	{
		struct state temp;
		for (int i = 0; i < 4; i++)
		{
			for (int j = 0; j < 4; j++)
			{
				temp.stateByte[i][j] = s1->stateByte[i][j] ^ s2->stateByte[i][j];
			}
		}
		return temp;
	}

	// Rotates the byteword cyclically
	word RotWord(struct word input)
	{
		word result;
		for (int i = 0; i < 4; i++)
		{
			result.byteWord[i] = input.byteWord[((i + 1) % 4)];
		}
		return result;
	}

	//Print Word Values
	void PrintWord(struct word input)
	{
		cout << endl;
		for (int i = 0; i < 4; i++)
		{
			cout << setfill('0') << setw(2) << hex << to_integer<int>(input.byteWord[i]) << "\t";
		}
	}

	// Shift rows function
	struct state ShiftRow(struct state s)
	{
		state temp;
		for (int i = 0; i < 4; i++)
		{
			for (int j = 0; j < 4; j++)
			{
				if (i == 0)
				{
					temp.stateByte[i][j] = s.stateByte[i][j];
				}
				else if (i == 1)
				{
					temp.stateByte[i][j] = s.stateByte[i][((j + 1) % 4)];
				}
				else if (i == 2)
				{
					temp.stateByte[i][j] = s.stateByte[i][((j + 2) % 4)];
				}
				else
				{
					temp.stateByte[i][j] = s.stateByte[i][((j + 3) % 4)];
				}

			}
		}
		return temp;
	}

	// Inverse Shift rows function
	struct state InvShiftRow(struct state s)
	{
		state temp;
		for (int i = 0; i < 4; i++)
		{
			for (int j = 0; j < 4; j++)
			{
				if (i == 0)
				{
					temp.stateByte[i][j] = s.stateByte[i][j];
				}
				else if (i == 1)
				{
					temp.stateByte[i][(j + 1) % 4] = s.stateByte[i][j];
				}
				else if (i == 2)
				{
					temp.stateByte[i][((j + 2) % 4)] = s.stateByte[i][j];
				}
				else
				{
					temp.stateByte[i][((j + 3) % 4)] = s.stateByte[i][j];
				}

			}
		}
		return temp;
	}

	//used in MixColumns and inverse MixColumns to multiply a byte with one of the constants
	std::byte mixMultiply(std::byte variable, std::byte constantByte)
	{
		//check which constant is being multiplied
		if (constantByte == std::byte{ 0x02 })
		{
			//if it is 0x02, check the highest order bit for overflow
			//this condition depends on secret data, potential timing opportunity if the XOR with 0x00 is optimized away
			if ((variable >> 7) == std::byte{ 0x01 })
				return ((variable << 1) ^ std::byte{ 0x1b });
			else
				return ((variable << 1) ^ std::byte{ 0x00 });
		}
		else if (constantByte == std::byte{ 0x03 })
		{
			//in the case of 0x03 we call again for 0x02 and the variable value, before XORing with its original value
			return mixMultiply(variable, std::byte{ 0x02 }) ^ variable;
		}
		else if (constantByte == std::byte{ 0x09 })
		{
			//in the case of 0x09, we turn it into 0x08 + 0x01
			return mixMultiply(mixMultiply(mixMultiply(variable, std::byte{ 0x02 }), std::byte{ 0x02 }), std::byte{ 0x02 }) ^ variable;
		}
		else if (constantByte == std::byte{ 0x0b })
		{
			//in the case of 0x0b, we turn it into 0x08 + 0x02 + 0x01
			return mixMultiply(mixMultiply(mixMultiply(variable, std::byte{ 0x02 }), std::byte{ 0x02 }), std::byte{ 0x02 }) ^ mixMultiply(variable, std::byte{ 0x02 }) ^ variable;
		}
		else if (constantByte == std::byte{ 0x0d })
		{
			//in the case of 0x0d, we turn it into 0x08 + 0x04 + 0x01
			return mixMultiply(mixMultiply(mixMultiply(variable, std::byte{ 0x02 }), std::byte{ 0x02 }), std::byte{ 0x02 }) ^ mixMultiply(mixMultiply(variable, std::byte{ 0x02 }), std::byte{ 0x02 }) ^ variable;
		}
		else if (constantByte == std::byte{ 0x0e })
		{
			//in the case of 0x0e, we turn it into 0x08 + 0x04 + 0x02
			return mixMultiply(mixMultiply(mixMultiply(variable, std::byte{ 0x02 }), std::byte{ 0x02 }), std::byte{ 0x02 }) ^ mixMultiply(mixMultiply(variable, std::byte{ 0x02 }), std::byte{ 0x02 }) ^ mixMultiply(variable, std::byte{ 0x02 });
		}
		return std::byte{ 0x00 };
	}

	//after shifting rows, mix columns to provide diffusion over whole block
	struct state MixColumns(struct state s)
	{
		//operate on one column at a time
		for (int column = 0; column < 4; column++)
		{
			std::byte s0c = s.stateByte[0][column];
			std::byte s1c = s.stateByte[1][column];
			std::byte s2c = s.stateByte[2][column];
			std::byte s3c = s.stateByte[3][column];

			//calculate the matrix multiplication to get the mixed columns
			s.stateByte[0][column] = (mixMultiply(s0c, std::byte{ 0x02 })) ^ (mixMultiply(s1c, std::byte{ 0x03 })) ^ s2c ^ s3c;
			s.stateByte[1][column] = s0c ^ (mixMultiply(s1c, std::byte{ 0x02 })) ^ (mixMultiply(s2c, std::byte{ 0x03 })) ^ s3c;
			s.stateByte[2][column] = s0c ^ s1c ^ (mixMultiply(s2c, std::byte{ 0x02 })) ^ (mixMultiply(s3c, std::byte{ 0x03 }));
			s.stateByte[3][column] = (mixMultiply(s0c, std::byte{ 0x03 })) ^ s1c ^ s2c ^ (mixMultiply(s3c, std::byte{ 0x02 }));

		}
		return s;
	}

	//inverse mix columns, used in decryption
	struct state InvMixColumns(struct state s)
	{
		//operate on one column at a time
		for (int column = 0; column < 4; column++)
		{
			std::byte s0c = s.stateByte[0][column];
			std::byte s1c = s.stateByte[1][column];
			std::byte s2c = s.stateByte[2][column];
			std::byte s3c = s.stateByte[3][column];

			//calculate the matrix multiplication to get the mixed columns
			s.stateByte[0][column] = (mixMultiply(s0c, std::byte{ 0x0e })) ^ (mixMultiply(s1c, std::byte{ 0x0b })) ^ (mixMultiply(s2c, std::byte{ 0x0d })) ^ (mixMultiply(s3c, std::byte{ 0x09 }));
			s.stateByte[1][column] = (mixMultiply(s0c, std::byte{ 0x09 })) ^ (mixMultiply(s1c, std::byte{ 0x0e })) ^ (mixMultiply(s2c, std::byte{ 0x0b })) ^ (mixMultiply(s3c, std::byte{ 0x0d }));
			s.stateByte[2][column] = (mixMultiply(s0c, std::byte{ 0x0d })) ^ (mixMultiply(s1c, std::byte{ 0x09 })) ^ (mixMultiply(s2c, std::byte{ 0x0e })) ^ (mixMultiply(s3c, std::byte{ 0x0b }));
			s.stateByte[3][column] = (mixMultiply(s0c, std::byte{ 0x0b })) ^ (mixMultiply(s1c, std::byte{ 0x0d })) ^ (mixMultiply(s2c, std::byte{ 0x09 })) ^ (mixMultiply(s3c, std::byte{ 0x0e }));

		}
		return s;
	}

	//use formatFlag 'c' = character, 'h' = hex, 'i' = integer to change the output format
	void PrintState(struct state s, char formatFlag)
	{
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				if (formatFlag == 'c')
					cout << (char)s.stateByte[i][j] << "\t";
				else if (formatFlag == 'h')
					cout << setfill('0') << setw(2) << hex << to_integer<int>(s.stateByte[i][j]) << "\t";
				else if (formatFlag == 'i')
					cout << dec << to_integer<int>(s.stateByte[i][j]) << "\t";
			}
			cout << "\n";
		}
	}

	// Function to add round key
	struct state AddRoundKey(struct state input, struct word key[], int l, int u)
	{
		state temp;
		for (int i = 0; i < 4; i++)
		{
			for (int j = 0; j < 4; j++)
			{
				temp.stateByte[i][j] = input.stateByte[i][j] ^ key[j + l].byteWord[i];
			}
		}
		return temp;
	}

	struct word Rcon(int i)
	{
		word result;
		int temp = (int)pow(2, i - 1);
		// Converting to hex
		std::stringstream stream;
		std::byte multiplier = std::byte{ 0x1B };
		stream << std::hex << temp;
		result.byteWord[0] = std::byte(temp);
		// when the value overflows xor with 0x1B
		if (i > 8)
		{
			result.byteWord[0] = result.byteWord[0] ^ multiplier;
			for (int k = 9; k < i; k++)
			{
				temp = 2 * to_integer<int>(result.byteWord[0]);
				stream << std::hex << temp;
				result.byteWord[0] = std::byte(temp);
			}
		}
		for (int j = 1; j < 4; j++)
		{
			result.byteWord[j] = std::byte{ 0x00 };
		}
		return result;
	}

	struct word performXor(struct word a, struct word b)
	{
		word result;
		for (int i = 0; i < 4; i++)
		{
			result.byteWord[i] = a.byteWord[i] ^ b.byteWord[i];
		}
		return result;
	}

	// Key Expansion function
	void keyExpansion()
	{
		word temp;

		// First Nk words are the original key

		//Expanding the key for the remaining Nb*(Nr+1) - Nk words
		for (int i = Nk; i < Nb*(Nr + 1); i++)
		{
			temp = expandedKey[i - 1];

			if (i % Nk == 0)
			{
				temp = performXor(SubWord(RotWord(temp)), Rcon(i / Nk));
			}
			else if ((Nk > 6) && (i % Nk == 4))
			{
				temp = SubWord(temp);
			}

			expandedKey[i] = performXor(expandedKey[i - Nk], temp);
		}
	}

	//Encryption Function for a single block
	struct state blockEncrypt(struct state s)
	{

		// Add Round Key
		s = AddRoundKey(s, expandedKey, 0, Nb);
		for (int round = 0; round < Nr - 1; round++)
		{

			//SUB BYTES
			for (int i = 0; i < 4; i++)
			{
				for (int j = 0; j < 4; j++)
				{
					s.stateByte[i][j] = SubBytes(s.stateByte[i][j]);
				}
			}

			//SHIFT ROWS 
			s = ShiftRow(s);

			//MIX COLUMNS
			s = MixColumns(s);

			//ADD ROUND KEY
			s = AddRoundKey(s, expandedKey, (round + 1)*Nb, (round + 2)*Nb);
		}

		//SUB BYTES
		for (int i = 0; i < 4; i++)
		{
			for (int j = 0; j < 4; j++)
			{
				s.stateByte[i][j] = SubBytes(s.stateByte[i][j]);
			}
		}

		//SHIFT ROWS 
		s = ShiftRow(s);

		//ADD ROUND KEY
		s = AddRoundKey(s, expandedKey, Nr*Nb, (Nr + 1)*(Nb - 1));

		cout << "\n**** Output ****\n";
		PrintState(s, 'h');
		return s;
	}

	//
	struct state blockDecrypt(struct state s)
	{
		// Add Round Key
		s = AddRoundKey(s, expandedKey, Nr*Nb, (Nr + 1)*(Nb - 1));

		//cout << endl << endl;

		for (int round = Nr - 2; round >= 0; round--)
		{

			//INV SHIFT ROWS 
			s = InvShiftRow(s);

			//INV SUB BYTES
			for (int i = 0; i < 4; i++)
			{
				for (int j = 0; j < 4; j++)
				{
					s.stateByte[i][j] = InvSubBytes(s.stateByte[i][j]);
				}
			}

			//ADD ROUND KEY
			s = AddRoundKey(s, expandedKey, (round + 1)*Nb, (round + 2)*Nb);

			//INV MIX COLUMNS
			s = InvMixColumns(s);
		}

		//INV SHIFT ROWS 
		s = InvShiftRow(s);

		//INV SUB BYTES
		for (int i = 0; i < 4; i++)
		{
			for (int j = 0; j < 4; j++)
			{
				s.stateByte[i][j] = InvSubBytes(s.stateByte[i][j]);
			}
		}

		//ADD ROUND KEY 0, Nb
		s = AddRoundKey(s, expandedKey, 0, Nb);

		cout << "\n**** Output ****\n";
		PrintState(s, 'c');
		return s;
	}

};

int main()
{

	//Show the options available, encryption or decryption
	cout << "AES Encryption Application:" << endl <<
		"Enter 1 for Encryption\n" << endl <<
		"Enter 2 for Decryption" << endl << endl;

	//get the selection
	int choice = -1;
	cin >> choice;

	while (!(choice == 1 || choice == 2))
	{
		cout << "Enter 1 for encryption or 2 for decryption\n";
		cin >> choice;
	}

	//get the input and output files
	string inputFileString = "";
	string keyFileString = "";
	string outputFileString = "";

	cout << "Enter the input file" << endl;
	cin >> inputFileString;

	//open the input file
	ifstream inputFile;
	inputFile.open(inputFileString, ios::binary | ios::in);

	while (!inputFile)
	{
		cout << "Enter a valid input file" << endl;
		cin >> inputFileString;
		inputFile.open(inputFileString, ios::binary | ios::in);
	}

	cout << "Enter the key file" << endl;
	cin >> keyFileString;
	//test opening the key file
	ifstream keyFile;
	keyFile.open(keyFileString, ios::binary | ios::in);
	while (!keyFile)
	{
		cout << "Enter a valid key file" << endl;
		cin >> keyFileString;
		keyFile.open(keyFileString, ios::binary | ios::in);
	}
	keyFile.close();

	cout << "Enter the output file" << endl;
	cin >> outputFileString;



	//create an input and output vector of struct states, to contain blocks of input or output
	vector<struct state*> input;

	//read the input into the struct state array,
	//create an integer to contain the remaining number of bytes in the last block when it is found
	//how to handle the last block depends on the choice of encryption or decryption
		int paddingBytes = -1;
		while ((!inputFile.eof() && choice == 1) || (inputFile.peek() != istream::traits_type::eof() && choice == 2))
		{
			input.push_back(new struct state);
			for (int i = 0; i < 4; i++)
			{
				for (int j = 0; j < 4; j++)
				{
					//read from the input in order to get the next byte, if the end of file is reached it will set eof
					inputFile.read((char*)(&(input.back()->stateByte[j][i])), 1);
					//check if the eof is reached and number of padding bytes is not known yet
					if (inputFile.eof() && paddingBytes == -1)
					{
						//the amount of padding is the missing bytes, so the total amount we can have minus the amount we do have
						paddingBytes = 16 - (4 * i + j);
					}
					//check if the padding bytes are known at this point, and set the byte to that value if so
					if (paddingBytes != -1)
					{
						input.back()->stateByte[j][i] = (std::byte)paddingBytes;
					}
				}
			}
		}
		//close the input file when done reading
		inputFile.close();

	int keyOption;
	do
	{
		// Choosing key length.
		cout << endl << "1. AES128" << endl << "2. AES192" << endl << "3. AES256" << endl << "Enter your choice" << endl << endl;
		cin >> keyOption;
	} while (keyOption != 1 && keyOption != 2 && keyOption != 3);

	//Setting the values of Nk, Nr and Nb;
	AES aes;
	aes.setParameters(keyOption, keyFileString);

	//variable to contain the encrypt or decrypt output
	vector<std::byte>outputMessage;
	if (choice == 1)
	{
		outputMessage = aes.encrypt(input);
	}
	else if (choice == 2)
	{
		outputMessage = aes.decrypt(input);
	}
	//write the output
	//open the output file
	ofstream outputFile;
	outputFile.open(outputFileString, ios::binary | ios::trunc);
	while (!outputFile)
	{
		cout << "Enter a valid output file" << endl;
		cin >> outputFileString;
		outputFile.open(outputFileString, ios::binary | ios::trunc);
	}

	//write a block at a time, a byte at a time to the output file
	//for each block
	for (unsigned int i = 0; i < outputMessage.size(); i++)
	{
				outputFile << (char)outputMessage[i];
	}

	outputFile.close();

	//free dynamically allocated memory in the input
	for (unsigned int i = 0; i < input.size(); i++)
	{
		delete input[i];
	}

	string pause = "";
	getline(cin, pause);
	getline(cin, pause);

	return 0;
}