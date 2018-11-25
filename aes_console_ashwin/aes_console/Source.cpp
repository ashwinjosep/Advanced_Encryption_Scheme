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

	// S-Box Initialisation
	const std::byte sbox[256] = {
		std::byte{ 0x63 }, std::byte{ 0x7c }, std::byte{ 0x77 }, std::byte{ 0x7b },
		std::byte{ 0xf2 }, std::byte{ 0x6b }, std::byte{ 0x6f }, std::byte{ 0xc5 },
		std::byte{ 0x30 }, std::byte{ 0x01 }, std::byte{ 0x67 }, std::byte{ 0x2b },
		std::byte{ 0xfe }, std::byte{ 0xd7 }, std::byte{ 0xab }, std::byte{ 0x76 },
		std::byte{ 0xca }, std::byte{ 0x82 }, std::byte{ 0xc9 }, std::byte{ 0x7d },
		std::byte{ 0xfa }, std::byte{ 0x59 }, std::byte{ 0x47 }, std::byte{ 0xf0 },
		std::byte{ 0xad }, std::byte{ 0xd4 }, std::byte{ 0xa2 }, std::byte{ 0xaf },
		std::byte{ 0x9c }, std::byte{ 0xa4 }, std::byte{ 0x72 }, std::byte{ 0xc0 },
		std::byte{ 0xb7 }, std::byte{ 0xfd }, std::byte{ 0x93 }, std::byte{ 0x26 },
		std::byte{ 0x36 }, std::byte{ 0x3f }, std::byte{ 0xf7 }, std::byte{ 0xcc },
		std::byte{ 0x34 }, std::byte{ 0xa5 }, std::byte{ 0xe5 }, std::byte{ 0xf1 },
		std::byte{ 0x71 }, std::byte{ 0xd8 }, std::byte{ 0x31 }, std::byte{ 0x15 },
		std::byte{ 0x04 }, std::byte{ 0xc7 }, std::byte{ 0x23 }, std::byte{ 0xc3 },
		std::byte{ 0x18 }, std::byte{ 0x96 }, std::byte{ 0x05 }, std::byte{ 0x9a },
		std::byte{ 0x07 }, std::byte{ 0x12 }, std::byte{ 0x80 }, std::byte{ 0xe2 },
		std::byte{ 0xeb }, std::byte{ 0x27 }, std::byte{ 0xb2 }, std::byte{ 0x75 },
		std::byte{ 0x09 }, std::byte{ 0x83 }, std::byte{ 0x2c }, std::byte{ 0x1a },
		std::byte{ 0x1b }, std::byte{ 0x6e }, std::byte{ 0x5a }, std::byte{ 0xa0 },
		std::byte{ 0x52 }, std::byte{ 0x3b }, std::byte{ 0xd6 }, std::byte{ 0xb3 },
		std::byte{ 0x29 }, std::byte{ 0xe3 }, std::byte{ 0x2f }, std::byte{ 0x84 },
		std::byte{ 0x53 }, std::byte{ 0xd1 }, std::byte{ 0x00 }, std::byte{ 0xed },
		std::byte{ 0x20 }, std::byte{ 0xfc }, std::byte{ 0xb1 }, std::byte{ 0x5b },
		std::byte{ 0x6a }, std::byte{ 0xcb }, std::byte{ 0xbe }, std::byte{ 0x39 },
		std::byte{ 0x4a }, std::byte{ 0x4c }, std::byte{ 0x58 }, std::byte{ 0xcf },
		std::byte{ 0xd0 }, std::byte{ 0xef }, std::byte{ 0xaa }, std::byte{ 0xfb },
		std::byte{ 0x43 }, std::byte{ 0x4d }, std::byte{ 0x33 }, std::byte{ 0x85 },
		std::byte{ 0x45 }, std::byte{ 0xf9 }, std::byte{ 0x02 }, std::byte{ 0x7f },
		std::byte{ 0x50 }, std::byte{ 0x3c }, std::byte{ 0x9f }, std::byte{ 0xa8 },
		std::byte{ 0x51 }, std::byte{ 0xa3 }, std::byte{ 0x40 }, std::byte{ 0x8f },
		std::byte{ 0x92 }, std::byte{ 0x9d }, std::byte{ 0x38 }, std::byte{ 0xf5 },
		std::byte{ 0xbc }, std::byte{ 0xb6 }, std::byte{ 0xda }, std::byte{ 0x21 },
		std::byte{ 0x10 }, std::byte{ 0xff }, std::byte{ 0xf3 }, std::byte{ 0xd2 },
		std::byte{ 0xcd }, std::byte{ 0x0c }, std::byte{ 0x13 }, std::byte{ 0xec },
		std::byte{ 0x5f }, std::byte{ 0x97 }, std::byte{ 0x44 }, std::byte{ 0x17 },
		std::byte{ 0xc4 }, std::byte{ 0xa7 }, std::byte{ 0x7e }, std::byte{ 0x3d },
		std::byte{ 0x64 }, std::byte{ 0x5d }, std::byte{ 0x19 }, std::byte{ 0x73 },
		std::byte{ 0x60 }, std::byte{ 0x81 }, std::byte{ 0x4f }, std::byte{ 0xdc },
		std::byte{ 0x22 }, std::byte{ 0x2a }, std::byte{ 0x90 }, std::byte{ 0x88 },
		std::byte{ 0x46 }, std::byte{ 0xee }, std::byte{ 0xb8 }, std::byte{ 0x14 },
		std::byte{ 0xde }, std::byte{ 0x5e }, std::byte{ 0x0b }, std::byte{ 0xdb },
		std::byte{ 0xe0 }, std::byte{ 0x32 }, std::byte{ 0x3a }, std::byte{ 0x0a },
		std::byte{ 0x49 }, std::byte{ 0x06 }, std::byte{ 0x24 }, std::byte{ 0x5c },
		std::byte{ 0xc2 }, std::byte{ 0xd3 }, std::byte{ 0xac }, std::byte{ 0x62 },
		std::byte{ 0x91 }, std::byte{ 0x95 }, std::byte{ 0xe4 }, std::byte{ 0x79 },
		std::byte{ 0xe7 }, std::byte{ 0xc8 }, std::byte{ 0x37 }, std::byte{ 0x6d },
		std::byte{ 0x8d }, std::byte{ 0xd5 }, std::byte{ 0x4e }, std::byte{ 0xa9 },
		std::byte{ 0x6c }, std::byte{ 0x56 }, std::byte{ 0xf4 }, std::byte{ 0xea },
		std::byte{ 0x65 }, std::byte{ 0x7a }, std::byte{ 0xae }, std::byte{ 0x08 },
		std::byte{ 0xba }, std::byte{ 0x78 }, std::byte{ 0x25 }, std::byte{ 0x2e },
		std::byte{ 0x1c }, std::byte{ 0xa6 }, std::byte{ 0xb4 }, std::byte{ 0xc6 },
		std::byte{ 0xe8 }, std::byte{ 0xdd }, std::byte{ 0x74 }, std::byte{ 0x1f },
		std::byte{ 0x4b }, std::byte{ 0xbd }, std::byte{ 0x8b }, std::byte{ 0x8a },
		std::byte{ 0x70 }, std::byte{ 0x3e }, std::byte{ 0xb5 }, std::byte{ 0x66 },
		std::byte{ 0x48 }, std::byte{ 0x03 }, std::byte{ 0xf6 }, std::byte{ 0x0e },
		std::byte{ 0x61 }, std::byte{ 0x35 }, std::byte{ 0x57 }, std::byte{ 0xb9 },
		std::byte{ 0x86 }, std::byte{ 0xc1 }, std::byte{ 0x1d }, std::byte{ 0x9e },
		std::byte{ 0xe1 }, std::byte{ 0xf8 }, std::byte{ 0x98 }, std::byte{ 0x11 },
		std::byte{ 0x69 }, std::byte{ 0xd9 }, std::byte{ 0x8e }, std::byte{ 0x94 },
		std::byte{ 0x9b }, std::byte{ 0x1e }, std::byte{ 0x87 }, std::byte{ 0xe9 },
		std::byte{ 0xce }, std::byte{ 0x55 }, std::byte{ 0x28 }, std::byte{ 0xdf },
		std::byte{ 0x8c }, std::byte{ 0xa1 }, std::byte{ 0x89 }, std::byte{ 0x0d },
		std::byte{ 0xbf }, std::byte{ 0xe6 }, std::byte{ 0x42 }, std::byte{ 0x68 },
		std::byte{ 0x41 }, std::byte{ 0x99 }, std::byte{ 0x2d }, std::byte{ 0x0f },
		std::byte{ 0xb0 }, std::byte{ 0x54 }, std::byte{ 0xbb }, std::byte{ 0x16 }
	};

	// Inverse S-Box Initialisation
	const std::byte inv_sbox[256] = { 
		std::byte{ 0x52 }, std::byte{ 0x09 }, std::byte{ 0x6a }, std::byte{ 0xd5 },
		std::byte{ 0x30 }, std::byte{ 0x36 }, std::byte{ 0xa5 }, std::byte{ 0x38 },
		std::byte{ 0xbf }, std::byte{ 0x40 }, std::byte{ 0xa3 }, std::byte{ 0x9e },
		std::byte{ 0x81 }, std::byte{ 0xf3 }, std::byte{ 0xd7 }, std::byte{ 0xfb },
		std::byte{ 0x7c }, std::byte{ 0xe3 }, std::byte{ 0x39 }, std::byte{ 0x82 },
		std::byte{ 0x9b }, std::byte{ 0x2f }, std::byte{ 0xff }, std::byte{ 0x87 },
		std::byte{ 0x34 }, std::byte{ 0x8e }, std::byte{ 0x43 }, std::byte{ 0x44 },
		std::byte{ 0xc4 }, std::byte{ 0xde }, std::byte{ 0xe9 }, std::byte{ 0xcb },
		std::byte{ 0x54 }, std::byte{ 0x7b }, std::byte{ 0x94 }, std::byte{ 0x32 },
		std::byte{ 0xa6 }, std::byte{ 0xc2 }, std::byte{ 0x23 }, std::byte{ 0x3d },
		std::byte{ 0xee }, std::byte{ 0x4c }, std::byte{ 0x95 }, std::byte{ 0x0b },
		std::byte{ 0x42 }, std::byte{ 0xfa }, std::byte{ 0xc3 }, std::byte{ 0x4e },
		std::byte{ 0x08 }, std::byte{ 0x2e }, std::byte{ 0xa1 }, std::byte{ 0x66 },
		std::byte{ 0x28 }, std::byte{ 0xd9 }, std::byte{ 0x24 }, std::byte{ 0xb2 },
		std::byte{ 0x76 }, std::byte{ 0x5b }, std::byte{ 0xa2 }, std::byte{ 0x49 },
		std::byte{ 0x6d }, std::byte{ 0x8b }, std::byte{ 0xd1 }, std::byte{ 0x25 },
		std::byte{ 0x72 }, std::byte{ 0xf8 }, std::byte{ 0xf6 }, std::byte{ 0x64 },
		std::byte{ 0x86 }, std::byte{ 0x68 }, std::byte{ 0x98 }, std::byte{ 0x16 },
		std::byte{ 0xd4 }, std::byte{ 0xa4 }, std::byte{ 0x5c }, std::byte{ 0xcc },
		std::byte{ 0x5d }, std::byte{ 0x65 }, std::byte{ 0xb6 }, std::byte{ 0x92 },
		std::byte{ 0x6c }, std::byte{ 0x70 }, std::byte{ 0x48 }, std::byte{ 0x50 },
		std::byte{ 0xfd }, std::byte{ 0xed }, std::byte{ 0xb9 }, std::byte{ 0xda },
		std::byte{ 0x5e }, std::byte{ 0x15 }, std::byte{ 0x46 }, std::byte{ 0x57 },
		std::byte{ 0xa7 }, std::byte{ 0x8d }, std::byte{ 0x9d }, std::byte{ 0x84 },
		std::byte{ 0x90 }, std::byte{ 0xd8 }, std::byte{ 0xab }, std::byte{ 0x00 },
		std::byte{ 0x8c }, std::byte{ 0xbc }, std::byte{ 0xd3 }, std::byte{ 0x0a },
		std::byte{ 0xf7 }, std::byte{ 0xe4 }, std::byte{ 0x58 }, std::byte{ 0x05 },
		std::byte{ 0xb8 }, std::byte{ 0xb3 }, std::byte{ 0x45 }, std::byte{ 0x06 },
		std::byte{ 0xd0 }, std::byte{ 0x2c }, std::byte{ 0x1e }, std::byte{ 0x8f },
		std::byte{ 0xca }, std::byte{ 0x3f }, std::byte{ 0x0f }, std::byte{ 0x02 },
		std::byte{ 0xc1 }, std::byte{ 0xaf }, std::byte{ 0xbd }, std::byte{ 0x03 },
		std::byte{ 0x01 }, std::byte{ 0x13 }, std::byte{ 0x8a }, std::byte{ 0x6b },
		std::byte{ 0x3a }, std::byte{ 0x91 }, std::byte{ 0x11 }, std::byte{ 0x41 },
		std::byte{ 0x4f }, std::byte{ 0x67 }, std::byte{ 0xdc }, std::byte{ 0xea },
		std::byte{ 0x97 }, std::byte{ 0xf2 }, std::byte{ 0xcf }, std::byte{ 0xce },
		std::byte{ 0xf0 }, std::byte{ 0xb4 }, std::byte{ 0xe6 }, std::byte{ 0x73 },
		std::byte{ 0x96 }, std::byte{ 0xac }, std::byte{ 0x74 }, std::byte{ 0x22 },
		std::byte{ 0xe7 }, std::byte{ 0xad }, std::byte{ 0x35 }, std::byte{ 0x85 },
		std::byte{ 0xe2 }, std::byte{ 0xf9 }, std::byte{ 0x37 }, std::byte{ 0xe8 },
		std::byte{ 0x1c }, std::byte{ 0x75 }, std::byte{ 0xdf }, std::byte{ 0x6e },
		std::byte{ 0x47 }, std::byte{ 0xf1 }, std::byte{ 0x1a }, std::byte{ 0x71 },
		std::byte{ 0x1d }, std::byte{ 0x29 }, std::byte{ 0xc5 }, std::byte{ 0x89 },
		std::byte{ 0x6f }, std::byte{ 0xb7 }, std::byte{ 0x62 }, std::byte{ 0x0e },
		std::byte{ 0xaa }, std::byte{ 0x18 }, std::byte{ 0xbe }, std::byte{ 0x1b },
		std::byte{ 0xfc }, std::byte{ 0x56 }, std::byte{ 0x3e }, std::byte{ 0x4b },
		std::byte{ 0xc6 }, std::byte{ 0xd2 }, std::byte{ 0x79 }, std::byte{ 0x20 },
		std::byte{ 0x9a }, std::byte{ 0xdb }, std::byte{ 0xc0 }, std::byte{ 0xfe },
		std::byte{ 0x78 }, std::byte{ 0xcd }, std::byte{ 0x5a }, std::byte{ 0xf4 },
		std::byte{ 0x1f }, std::byte{ 0xdd }, std::byte{ 0xa8 }, std::byte{ 0x33 },
		std::byte{ 0x88 }, std::byte{ 0x07 }, std::byte{ 0xc7 }, std::byte{ 0x31 },
		std::byte{ 0xb1 }, std::byte{ 0x12 }, std::byte{ 0x10 }, std::byte{ 0x59 },
		std::byte{ 0x27 }, std::byte{ 0x80 }, std::byte{ 0xec }, std::byte{ 0x5f },
		std::byte{ 0x60 }, std::byte{ 0x51 }, std::byte{ 0x7f }, std::byte{ 0xa9 },
		std::byte{ 0x19 }, std::byte{ 0xb5 }, std::byte{ 0x4a }, std::byte{ 0x0d },
		std::byte{ 0x2d }, std::byte{ 0xe5 }, std::byte{ 0x7a }, std::byte{ 0x9f },
		std::byte{ 0x93 }, std::byte{ 0xc9 }, std::byte{ 0x9c }, std::byte{ 0xef },
		std::byte{ 0xa0 }, std::byte{ 0xe0 }, std::byte{ 0x3b }, std::byte{ 0x4d },
		std::byte{ 0xae }, std::byte{ 0x2a }, std::byte{ 0xf5 }, std::byte{ 0xb0 },
		std::byte{ 0xc8 }, std::byte{ 0xeb }, std::byte{ 0xbb }, std::byte{ 0x3c },
		std::byte{ 0x83 }, std::byte{ 0x53 }, std::byte{ 0x99 }, std::byte{ 0x61 },
		std::byte{ 0x17 }, std::byte{ 0x2b }, std::byte{ 0x04 }, std::byte{ 0x7e },
		std::byte{ 0xba }, std::byte{ 0x77 }, std::byte{ 0xd6 }, std::byte{ 0x26 },
		std::byte{ 0xe1 }, std::byte{ 0x69 }, std::byte{ 0x14 }, std::byte{ 0x63 },
		std::byte{ 0x55 }, std::byte{ 0x21 }, std::byte{ 0x0c }, std::byte{ 0x7d }
	};

	//IV variable
	state IV;

public:

	//message encryption method, at the multiple block level
	vector<struct state*> encrypt(vector<struct state*> input, struct state key)
	{
		//output vector of encrypted blocks
		vector<struct state*> output;

		output.push_back(new state);
		//GENERATE IV RANDOMLY AND SET AS THE FIRST OUTPUT BLOCK
		generateIV();
		*(output.back()) = blockEncrypt(IV, key);
		
		//for each input block, create an encrypted output block in CBC mode
		for (unsigned int i = 0; i < input.size(); i++)
		{
			output.push_back(new state);
			*(output.back()) = blockEncrypt(xorBlock(output[i],input[i]), key);
		}
		return output;
	}

	//message decryption method, at the multiple block level
	vector<struct state*> decrypt(vector<struct state*> input, struct state key)
	{
		//output vector of decrypted blocks
		vector<struct state*> output;
		//for each input block, xor with the previous block
		//IV is the first block, so start from i=1
		for (unsigned int i = 1; i < input.size(); i++)
		{
			output.push_back(new state);
			*(output.back()) = xorBlock(&blockDecrypt(*input[i], key), input[i-1]);
		}
		return output;
	}

private:

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

	//S-Box substitution
	std::byte SubBytes(std::byte a)
	{
		std::byte temp = sbox[to_integer<int>(a)];
		return temp;
	}

	std::byte InvSubBytes(std::byte a) {
		std::byte temp = inv_sbox[to_integer<int>(a)];
		return temp;
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
			if ((variable >> 7) == std::byte{ 0x01 })
				return ((variable << 1) ^ std::byte { 0x1b });
			else
				return ((variable << 1) ^ std::byte { 0x00 });
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
	void keyExpansion(state key, word w[], int Nk, int Nb, int Nr)
	{
		word temp;

		// Copying first Nk words to the expanded key
		for (int i = 0; i < Nk; i++)			// Loop runs 4 times since Nk = 4
		{
			for (int j = 0; j < 4; j++)		// Run for all 4 bytes in the word
			{
				w[i].byteWord[j] = key.stateByte[j][i];
			}
			//cout << endl << endl;
			//PrintWord(w[i]);
		}

		//Expanding the key for the remaining Nb*(Nr+1) - Nk words
		for (int i = Nk; i < Nb*(Nr + 1); i++)
		{
			temp = w[i - 1];

			//cout << "\n\ni : " << std::dec << i << " Temp " << endl;
			//PrintWord(temp);

			if (i % Nk == 0)
			{
				temp = performXor(SubWord(RotWord(temp)), Rcon(i / Nk));
			}
			else if ((Nk > 6) && (i % Nk == 4))
			{
				temp = SubWord(temp);
			}

			//cout << "\n\ni : " << std::dec << i << " After XOR with Rcon " << endl;
			//PrintWord(temp);

			w[i] = performXor(w[i - Nk], temp);

			//cout << "\n\ni : " << std::dec << i << " w[i] " << endl;
			//PrintWord(w[i]);

		}
	}

	//Encryption Function for a single block
	struct state blockEncrypt(struct state s, struct state key)
	{
		// Key Expansion 

		int Nk = 4;			// Key Length in words Variable for AES128
		int Nb = 4;			// Number of columns in state for AES128
		int Nr = 10;		// Number of rounds required for AES128

		// Expanded key should be of length Nb(Nr+1). Nb = 4 and Nr = 14 in AES256 implementation
		word expandedKey[60];

		//perform key expansion
		keyExpansion(key, expandedKey, Nk, Nb, Nr);

		// Add Round Key
		s = AddRoundKey(s, expandedKey, 0, Nb);
		for (int round = 0; round < Nr - 1; round++)
		{
			//cout << endl << endl << "**** Round : " << std::dec << (round + 1) << " ****" << endl;

			//cout << "\nstart of round\n";
			//PrintState(s, 'h');

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
	struct state blockDecrypt(struct state s, struct state key)
	{
		// Key Expansion 

		int Nk = 4;			// Key Length in words Variable for AES128
		int Nb = 4;			// Number of columns in state for AES128
		int Nr = 10;		// Number of rounds required for AES128

							// Expanded key should be of length Nb(Nr+1). Nb = 4 and Nr = 14 in AES256 implementation
		word expandedKey[60];

		//perform key expansion
		keyExpansion(key, expandedKey, Nk, Nb, Nr);

		// Add Round Key
		s = AddRoundKey(s, expandedKey, Nr*Nb, (Nr + 1)*(Nb - 1));

		//cout << endl << endl;

		for (int round = Nr - 2; round >= 0; round--)
		{
			//cout << endl << endl << "**** Round : " << std::dec << (round + 1) << " ****" << endl;

			//cout << "\nstart of round\n";
			//PrintState(s, 'h');

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
	string outputFileString = "";

	cout << "Enter the input file" << endl;
	//cin >> inputFileString;

	cout << "Enter the output file" << endl;
	//cin >> outputFileString;

	//open the input file
	ifstream inputFile;
	inputFile.open("inputFile.txt", ios::binary | ios::in);
	
	//create an input and output vector of struct states, to contain blocks of input or output
	vector<struct state*> input;
	//struct state test;
	//vector<struct state*> output;
	//TODO

	//read the input into the struct state array
	//create an integer to contain the remaining number of bytes in the last block when it is found
	int paddingBytes = -1;
	while (!inputFile.eof())
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
					paddingBytes = 16-(4 * i + j);
				}
				//check if the padding bytes are known at this point, and set the byte to that value if so
				if (paddingBytes != -1)
				{
					input.back()->stateByte[j][i] = (std::byte)paddingBytes;
				}
			}
		}
	}

	//open the key input file
	ifstream keyFile;
	keyFile.open("keyFile.txt", ios::binary | ios::in);

	//TODO, handle >128 bit keys, new struct?
	struct state key;
	while (!keyFile.eof())
	{
		for (int i = 0; i < 4; i++)
		{
			for (int j = 0; j < 4; j++)
			{
				keyFile.read((char*)(&(key.stateByte[j][i])), 1);
			}
		}
	}

	AES aes;
	vector<struct state*>output = aes.encrypt(input, key);
	vector<struct state*>decryptOutput = aes.decrypt(output, key);

	string pause = "";
	getline(cin, pause);
	getline(cin, pause);

	return 0;
}
