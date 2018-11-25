// AES_Console.cpp : Defines the entry point for the console application.
//

#include <iostream>
#include <string>
#include <math.h>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <bitset>
#include <iomanip>
#include <fstream>
#include <vector>
#include <chrono>

using namespace std;

// Structure for state type
struct state
{
	byte stateByte[4][4];
};

//Structure for word type
struct word
{
	byte byteWord[4];
};

class AES {

	// S-Box Initialisation
	const byte sbox[256] = {
		byte{ 0x63 }, byte{ 0x7c }, byte{ 0x77 }, byte{ 0x7b },
		byte{ 0xf2 }, byte{ 0x6b }, byte{ 0x6f }, byte{ 0xc5 },
		byte{ 0x30 }, byte{ 0x01 }, byte{ 0x67 }, byte{ 0x2b },
		byte{ 0xfe }, byte{ 0xd7 }, byte{ 0xab }, byte{ 0x76 },
		byte{ 0xca }, byte{ 0x82 }, byte{ 0xc9 }, byte{ 0x7d },
		byte{ 0xfa }, byte{ 0x59 }, byte{ 0x47 }, byte{ 0xf0 },
		byte{ 0xad }, byte{ 0xd4 }, byte{ 0xa2 }, byte{ 0xaf },
		byte{ 0x9c }, byte{ 0xa4 }, byte{ 0x72 }, byte{ 0xc0 },
		byte{ 0xb7 }, byte{ 0xfd }, byte{ 0x93 }, byte{ 0x26 },
		byte{ 0x36 }, byte{ 0x3f }, byte{ 0xf7 }, byte{ 0xcc },
		byte{ 0x34 }, byte{ 0xa5 }, byte{ 0xe5 }, byte{ 0xf1 },
		byte{ 0x71 }, byte{ 0xd8 }, byte{ 0x31 }, byte{ 0x15 },
		byte{ 0x04 }, byte{ 0xc7 }, byte{ 0x23 }, byte{ 0xc3 },
		byte{ 0x18 }, byte{ 0x96 }, byte{ 0x05 }, byte{ 0x9a },
		byte{ 0x07 }, byte{ 0x12 }, byte{ 0x80 }, byte{ 0xe2 },
		byte{ 0xeb }, byte{ 0x27 }, byte{ 0xb2 }, byte{ 0x75 },
		byte{ 0x09 }, byte{ 0x83 }, byte{ 0x2c }, byte{ 0x1a },
		byte{ 0x1b }, byte{ 0x6e }, byte{ 0x5a }, byte{ 0xa0 },
		byte{ 0x52 }, byte{ 0x3b }, byte{ 0xd6 }, byte{ 0xb3 },
		byte{ 0x29 }, byte{ 0xe3 }, byte{ 0x2f }, byte{ 0x84 },
		byte{ 0x53 }, byte{ 0xd1 }, byte{ 0x00 }, byte{ 0xed },
		byte{ 0x20 }, byte{ 0xfc }, byte{ 0xb1 }, byte{ 0x5b },
		byte{ 0x6a }, byte{ 0xcb }, byte{ 0xbe }, byte{ 0x39 },
		byte{ 0x4a }, byte{ 0x4c }, byte{ 0x58 }, byte{ 0xcf },
		byte{ 0xd0 }, byte{ 0xef }, byte{ 0xaa }, byte{ 0xfb },
		byte{ 0x43 }, byte{ 0x4d }, byte{ 0x33 }, byte{ 0x85 },
		byte{ 0x45 }, byte{ 0xf9 }, byte{ 0x02 }, byte{ 0x7f },
		byte{ 0x50 }, byte{ 0x3c }, byte{ 0x9f }, byte{ 0xa8 },
		byte{ 0x51 }, byte{ 0xa3 }, byte{ 0x40 }, byte{ 0x8f },
		byte{ 0x92 }, byte{ 0x9d }, byte{ 0x38 }, byte{ 0xf5 },
		byte{ 0xbc }, byte{ 0xb6 }, byte{ 0xda }, byte{ 0x21 },
		byte{ 0x10 }, byte{ 0xff }, byte{ 0xf3 }, byte{ 0xd2 },
		byte{ 0xcd }, byte{ 0x0c }, byte{ 0x13 }, byte{ 0xec },
		byte{ 0x5f }, byte{ 0x97 }, byte{ 0x44 }, byte{ 0x17 },
		byte{ 0xc4 }, byte{ 0xa7 }, byte{ 0x7e }, byte{ 0x3d },
		byte{ 0x64 }, byte{ 0x5d }, byte{ 0x19 }, byte{ 0x73 },
		byte{ 0x60 }, byte{ 0x81 }, byte{ 0x4f }, byte{ 0xdc },
		byte{ 0x22 }, byte{ 0x2a }, byte{ 0x90 }, byte{ 0x88 },
		byte{ 0x46 }, byte{ 0xee }, byte{ 0xb8 }, byte{ 0x14 },
		byte{ 0xde }, byte{ 0x5e }, byte{ 0x0b }, byte{ 0xdb },
		byte{ 0xe0 }, byte{ 0x32 }, byte{ 0x3a }, byte{ 0x0a },
		byte{ 0x49 }, byte{ 0x06 }, byte{ 0x24 }, byte{ 0x5c },
		byte{ 0xc2 }, byte{ 0xd3 }, byte{ 0xac }, byte{ 0x62 },
		byte{ 0x91 }, byte{ 0x95 }, byte{ 0xe4 }, byte{ 0x79 },
		byte{ 0xe7 }, byte{ 0xc8 }, byte{ 0x37 }, byte{ 0x6d },
		byte{ 0x8d }, byte{ 0xd5 }, byte{ 0x4e }, byte{ 0xa9 },
		byte{ 0x6c }, byte{ 0x56 }, byte{ 0xf4 }, byte{ 0xea },
		byte{ 0x65 }, byte{ 0x7a }, byte{ 0xae }, byte{ 0x08 },
		byte{ 0xba }, byte{ 0x78 }, byte{ 0x25 }, byte{ 0x2e },
		byte{ 0x1c }, byte{ 0xa6 }, byte{ 0xb4 }, byte{ 0xc6 },
		byte{ 0xe8 }, byte{ 0xdd }, byte{ 0x74 }, byte{ 0x1f },
		byte{ 0x4b }, byte{ 0xbd }, byte{ 0x8b }, byte{ 0x8a },
		byte{ 0x70 }, byte{ 0x3e }, byte{ 0xb5 }, byte{ 0x66 },
		byte{ 0x48 }, byte{ 0x03 }, byte{ 0xf6 }, byte{ 0x0e },
		byte{ 0x61 }, byte{ 0x35 }, byte{ 0x57 }, byte{ 0xb9 },
		byte{ 0x86 }, byte{ 0xc1 }, byte{ 0x1d }, byte{ 0x9e },
		byte{ 0xe1 }, byte{ 0xf8 }, byte{ 0x98 }, byte{ 0x11 },
		byte{ 0x69 }, byte{ 0xd9 }, byte{ 0x8e }, byte{ 0x94 },
		byte{ 0x9b }, byte{ 0x1e }, byte{ 0x87 }, byte{ 0xe9 },
		byte{ 0xce }, byte{ 0x55 }, byte{ 0x28 }, byte{ 0xdf },
		byte{ 0x8c }, byte{ 0xa1 }, byte{ 0x89 }, byte{ 0x0d },
		byte{ 0xbf }, byte{ 0xe6 }, byte{ 0x42 }, byte{ 0x68 },
		byte{ 0x41 }, byte{ 0x99 }, byte{ 0x2d }, byte{ 0x0f },
		byte{ 0xb0 }, byte{ 0x54 }, byte{ 0xbb }, byte{ 0x16 }
	};

	// Inverse S-Box Initialisation
	const byte inv_sbox[256] = { 
		byte{ 0x52 }, byte{ 0x09 }, byte{ 0x6a }, byte{ 0xd5 },
		byte{ 0x30 }, byte{ 0x36 }, byte{ 0xa5 }, byte{ 0x38 },
		byte{ 0xbf }, byte{ 0x40 }, byte{ 0xa3 }, byte{ 0x9e },
		byte{ 0x81 }, byte{ 0xf3 }, byte{ 0xd7 }, byte{ 0xfb },
		byte{ 0x7c }, byte{ 0xe3 }, byte{ 0x39 }, byte{ 0x82 },
		byte{ 0x9b }, byte{ 0x2f }, byte{ 0xff }, byte{ 0x87 },
		byte{ 0x34 }, byte{ 0x8e }, byte{ 0x43 }, byte{ 0x44 },
		byte{ 0xc4 }, byte{ 0xde }, byte{ 0xe9 }, byte{ 0xcb },
		byte{ 0x54 }, byte{ 0x7b }, byte{ 0x94 }, byte{ 0x32 },
		byte{ 0xa6 }, byte{ 0xc2 }, byte{ 0x23 }, byte{ 0x3d },
		byte{ 0xee }, byte{ 0x4c }, byte{ 0x95 }, byte{ 0x0b },
		byte{ 0x42 }, byte{ 0xfa }, byte{ 0xc3 }, byte{ 0x4e },
		byte{ 0x08 }, byte{ 0x2e }, byte{ 0xa1 }, byte{ 0x66 },
		byte{ 0x28 }, byte{ 0xd9 }, byte{ 0x24 }, byte{ 0xb2 },
		byte{ 0x76 }, byte{ 0x5b }, byte{ 0xa2 }, byte{ 0x49 },
		byte{ 0x6d }, byte{ 0x8b }, byte{ 0xd1 }, byte{ 0x25 },
		byte{ 0x72 }, byte{ 0xf8 }, byte{ 0xf6 }, byte{ 0x64 },
		byte{ 0x86 }, byte{ 0x68 }, byte{ 0x98 }, byte{ 0x16 },
		byte{ 0xd4 }, byte{ 0xa4 }, byte{ 0x5c }, byte{ 0xcc },
		byte{ 0x5d }, byte{ 0x65 }, byte{ 0xb6 }, byte{ 0x92 },
		byte{ 0x6c }, byte{ 0x70 }, byte{ 0x48 }, byte{ 0x50 },
		byte{ 0xfd }, byte{ 0xed }, byte{ 0xb9 }, byte{ 0xda },
		byte{ 0x5e }, byte{ 0x15 }, byte{ 0x46 }, byte{ 0x57 },
		byte{ 0xa7 }, byte{ 0x8d }, byte{ 0x9d }, byte{ 0x84 },
		byte{ 0x90 }, byte{ 0xd8 }, byte{ 0xab }, byte{ 0x00 },
		byte{ 0x8c }, byte{ 0xbc }, byte{ 0xd3 }, byte{ 0x0a },
		byte{ 0xf7 }, byte{ 0xe4 }, byte{ 0x58 }, byte{ 0x05 },
		byte{ 0xb8 }, byte{ 0xb3 }, byte{ 0x45 }, byte{ 0x06 },
		byte{ 0xd0 }, byte{ 0x2c }, byte{ 0x1e }, byte{ 0x8f },
		byte{ 0xca }, byte{ 0x3f }, byte{ 0x0f }, byte{ 0x02 },
		byte{ 0xc1 }, byte{ 0xaf }, byte{ 0xbd }, byte{ 0x03 },
		byte{ 0x01 }, byte{ 0x13 }, byte{ 0x8a }, byte{ 0x6b },
		byte{ 0x3a }, byte{ 0x91 }, byte{ 0x11 }, byte{ 0x41 },
		byte{ 0x4f }, byte{ 0x67 }, byte{ 0xdc }, byte{ 0xea },
		byte{ 0x97 }, byte{ 0xf2 }, byte{ 0xcf }, byte{ 0xce },
		byte{ 0xf0 }, byte{ 0xb4 }, byte{ 0xe6 }, byte{ 0x73 },
		byte{ 0x96 }, byte{ 0xac }, byte{ 0x74 }, byte{ 0x22 },
		byte{ 0xe7 }, byte{ 0xad }, byte{ 0x35 }, byte{ 0x85 },
		byte{ 0xe2 }, byte{ 0xf9 }, byte{ 0x37 }, byte{ 0xe8 },
		byte{ 0x1c }, byte{ 0x75 }, byte{ 0xdf }, byte{ 0x6e },
		byte{ 0x47 }, byte{ 0xf1 }, byte{ 0x1a }, byte{ 0x71 },
		byte{ 0x1d }, byte{ 0x29 }, byte{ 0xc5 }, byte{ 0x89 },
		byte{ 0x6f }, byte{ 0xb7 }, byte{ 0x62 }, byte{ 0x0e },
		byte{ 0xaa }, byte{ 0x18 }, byte{ 0xbe }, byte{ 0x1b },
		byte{ 0xfc }, byte{ 0x56 }, byte{ 0x3e }, byte{ 0x4b },
		byte{ 0xc6 }, byte{ 0xd2 }, byte{ 0x79 }, byte{ 0x20 },
		byte{ 0x9a }, byte{ 0xdb }, byte{ 0xc0 }, byte{ 0xfe },
		byte{ 0x78 }, byte{ 0xcd }, byte{ 0x5a }, byte{ 0xf4 },
		byte{ 0x1f }, byte{ 0xdd }, byte{ 0xa8 }, byte{ 0x33 },
		byte{ 0x88 }, byte{ 0x07 }, byte{ 0xc7 }, byte{ 0x31 },
		byte{ 0xb1 }, byte{ 0x12 }, byte{ 0x10 }, byte{ 0x59 },
		byte{ 0x27 }, byte{ 0x80 }, byte{ 0xec }, byte{ 0x5f },
		byte{ 0x60 }, byte{ 0x51 }, byte{ 0x7f }, byte{ 0xa9 },
		byte{ 0x19 }, byte{ 0xb5 }, byte{ 0x4a }, byte{ 0x0d },
		byte{ 0x2d }, byte{ 0xe5 }, byte{ 0x7a }, byte{ 0x9f },
		byte{ 0x93 }, byte{ 0xc9 }, byte{ 0x9c }, byte{ 0xef },
		byte{ 0xa0 }, byte{ 0xe0 }, byte{ 0x3b }, byte{ 0x4d },
		byte{ 0xae }, byte{ 0x2a }, byte{ 0xf5 }, byte{ 0xb0 },
		byte{ 0xc8 }, byte{ 0xeb }, byte{ 0xbb }, byte{ 0x3c },
		byte{ 0x83 }, byte{ 0x53 }, byte{ 0x99 }, byte{ 0x61 },
		byte{ 0x17 }, byte{ 0x2b }, byte{ 0x04 }, byte{ 0x7e },
		byte{ 0xba }, byte{ 0x77 }, byte{ 0xd6 }, byte{ 0x26 },
		byte{ 0xe1 }, byte{ 0x69 }, byte{ 0x14 }, byte{ 0x63 },
		byte{ 0x55 }, byte{ 0x21 }, byte{ 0x0c }, byte{ 0x7d }
	};

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

		////HARDCODED FOR NOW
		//for (int i = 0; i < 4; i++)
		//{
		//	for (int j = 0; j < 4; j++)
		//	{
		//		output.back()->stateByte[i][j] = byte{ 0x01 };
		//	}
		//}
		
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

	// Random IV Generator using timestamp nonce
	void generateIV()
	{
		using namespace std::chrono;
		nanoseconds ns = duration_cast<nanoseconds>(system_clock::now().time_since_epoch());
		std::stringstream stream;
		long long int value = ns.count();
		int tempWord;
		for (int i = 0; i < 4; i++)
		{
			for (int j = 0; j < 4; j++)
			{
				tempWord = value % 10;
				stream << std::hex << tempWord;
				IV.stateByte[i][j] = std::byte(tempWord);
				value /= 10;
			}
		}
	}

	//S-Box substitution
	byte SubBytes(byte a)
	{
		byte temp = sbox[to_integer<int>(a)];
		return temp;
	}

	byte InvSubBytes(byte a) {
		byte temp = inv_sbox[to_integer<int>(a)];
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
	byte mixMultiply(byte variable, byte constantByte)
	{
		//check which constant is being multiplied
		if (constantByte == byte{ 0x02 })
		{
			//if it is 0x02, check the highest order bit for overflow
			if ((variable >> 7) == byte{ 0x01 })
				return ((variable << 1) ^ byte { 0x1b });
			else
				return ((variable << 1) ^ byte { 0x00 });
		}
		else if (constantByte == byte{ 0x03 })
		{
			//in the case of 0x03 we call again for 0x02 and the variable value, before XORing with its original value
			return mixMultiply(variable, byte{ 0x02 }) ^ variable;
		}
		else if (constantByte == byte{ 0x09 })
		{
			//in the case of 0x09, we turn it into 0x08 + 0x01
			return mixMultiply(mixMultiply(mixMultiply(variable, byte{ 0x02 }), byte{ 0x02 }), byte{ 0x02 }) ^ variable;
		}
		else if (constantByte == byte{ 0x0b })
		{
			//in the case of 0x0b, we turn it into 0x08 + 0x02 + 0x01
			return mixMultiply(mixMultiply(mixMultiply(variable, byte{ 0x02 }), byte{ 0x02 }), byte{ 0x02 }) ^ mixMultiply(variable, byte{ 0x02 }) ^ variable;
		}
		else if (constantByte == byte{ 0x0d })
		{
			//in the case of 0x0d, we turn it into 0x08 + 0x04 + 0x01
			return mixMultiply(mixMultiply(mixMultiply(variable, byte{ 0x02 }), byte{ 0x02 }), byte{ 0x02 }) ^ mixMultiply(mixMultiply(variable, byte{ 0x02 }), byte{ 0x02 }) ^ variable;
		}
		else if (constantByte == byte{ 0x0e })
		{
			//in the case of 0x0e, we turn it into 0x08 + 0x04 + 0x02
			return mixMultiply(mixMultiply(mixMultiply(variable, byte{ 0x02 }), byte{ 0x02 }), byte{ 0x02 }) ^ mixMultiply(mixMultiply(variable, byte{ 0x02 }), byte{ 0x02 }) ^ mixMultiply(variable, byte{ 0x02 });
		}
		return byte{ 0x00 };
	}

	//after shifting rows, mix columns to provide diffusion over whole block
	struct state MixColumns(struct state s)
	{
		//operate on one column at a time
		for (int column = 0; column < 4; column++)
		{
			byte s0c = s.stateByte[0][column];
			byte s1c = s.stateByte[1][column];
			byte s2c = s.stateByte[2][column];
			byte s3c = s.stateByte[3][column];

			//calculate the matrix multiplication to get the mixed columns
			s.stateByte[0][column] = (mixMultiply(s0c, byte{ 0x02 })) ^ (mixMultiply(s1c, byte{ 0x03 })) ^ s2c ^ s3c;
			s.stateByte[1][column] = s0c ^ (mixMultiply(s1c, byte{ 0x02 })) ^ (mixMultiply(s2c, byte{ 0x03 })) ^ s3c;
			s.stateByte[2][column] = s0c ^ s1c ^ (mixMultiply(s2c, byte{ 0x02 })) ^ (mixMultiply(s3c, byte{ 0x03 }));
			s.stateByte[3][column] = (mixMultiply(s0c, byte{ 0x03 })) ^ s1c ^ s2c ^ (mixMultiply(s3c, byte{ 0x02 }));

		}
		return s;
	}

	//inverse mix columns, used in decryption
	struct state InvMixColumns(struct state s)
	{
		//operate on one column at a time
		for (int column = 0; column < 4; column++)
		{
			byte s0c = s.stateByte[0][column];
			byte s1c = s.stateByte[1][column];
			byte s2c = s.stateByte[2][column];
			byte s3c = s.stateByte[3][column];

			//calculate the matrix multiplication to get the mixed columns
			s.stateByte[0][column] = (mixMultiply(s0c, byte{ 0x0e })) ^ (mixMultiply(s1c, byte{ 0x0b })) ^ (mixMultiply(s2c, byte{ 0x0d })) ^ (mixMultiply(s3c, byte{ 0x09 }));
			s.stateByte[1][column] = (mixMultiply(s0c, byte{ 0x09 })) ^ (mixMultiply(s1c, byte{ 0x0e })) ^ (mixMultiply(s2c, byte{ 0x0b })) ^ (mixMultiply(s3c, byte{ 0x0d }));
			s.stateByte[2][column] = (mixMultiply(s0c, byte{ 0x0d })) ^ (mixMultiply(s1c, byte{ 0x09 })) ^ (mixMultiply(s2c, byte{ 0x0e })) ^ (mixMultiply(s3c, byte{ 0x0b }));
			s.stateByte[3][column] = (mixMultiply(s0c, byte{ 0x0b })) ^ (mixMultiply(s1c, byte{ 0x0d })) ^ (mixMultiply(s2c, byte{ 0x09 })) ^ (mixMultiply(s3c, byte{ 0x0e }));

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
		byte multiplier = byte{ 0x1B };
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
			result.byteWord[j] = byte{ 0x00 };
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

	//
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
					input.back()->stateByte[j][i] = (byte)paddingBytes;
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
