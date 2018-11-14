// AES_Console.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <iostream>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <bitset>
#include <iomanip>

using namespace std;

byte sbox[256] = { byte{ 0x63 }, byte{ 0x7c }, byte{ 0x77 }, byte{ 0x7b }, byte{ 0xf2 }, byte{ 0x6b }, byte{ 0x6f }, byte{ 0xc5 }, byte{ 0x30 }, byte{ 0x01 }, byte{ 0x67 }, byte{ 0x2b }, byte{ 0xfe }, byte{ 0xd7 }, byte{ 0xab }, byte{ 0x76 }, byte{ 0xca }, byte{ 0x82 }, byte{ 0xc9 }, byte{ 0x7d }, byte{ 0xfa }, byte{ 0x59 }, byte{ 0x47 }, byte{ 0xf0 }, byte{ 0xad }, byte{ 0xd4 }, byte{ 0xa2 }, byte{ 0xaf }, byte{ 0x9c }, byte{ 0xa4 }, byte{ 0x72 }, byte{ 0xc0 }, byte{ 0xb7 }, byte{ 0xfd }, byte{ 0x93 }, byte{ 0x26 }, byte{ 0x36 }, byte{ 0x3f }, byte{ 0xf7 }, byte{ 0xcc }, byte{ 0x34 }, byte{ 0xa5 }, byte{ 0xe5 }, byte{ 0xf1 }, byte{ 0x71 }, byte{ 0xd8 }, byte{ 0x31 }, byte{ 0x15 }, byte{ 0x04 }, byte{ 0xc7 }, byte{ 0x23 }, byte{ 0xc3 }, byte{ 0x18 }, byte{ 0x96 }, byte{ 0x05 }, byte{ 0x9a }, byte{ 0x07 }, byte{ 0x12 }, byte{ 0x80 }, byte{ 0xe2 }, byte{ 0xeb }, byte{ 0x27 }, byte{ 0xb2 }, byte{ 0x75 }, byte{ 0x09 }, byte{ 0x83 }, byte{ 0x2c }, byte{ 0x1a }, byte{ 0x1b }, byte{ 0x6e }, byte{ 0x5a }, byte{ 0xa0 }, byte{ 0x52 }, byte{ 0x3b }, byte{ 0xd6 }, byte{ 0xb3 }, byte{ 0x29 }, byte{ 0xe3 }, byte{ 0x2f }, byte{ 0x84 }, byte{ 0x53 }, byte{ 0xd1 }, byte{ 0x00 }, byte{ 0xed }, byte{ 0x20 }, byte{ 0xfc }, byte{ 0xb1 }, byte{ 0x5b }, byte{ 0x6a }, byte{ 0xcb }, byte{ 0xbe }, byte{ 0x39 }, byte{ 0x4a }, byte{ 0x4c }, byte{ 0x58 }, byte{ 0xcf }, byte{ 0xd0 }, byte{ 0xef }, byte{ 0xaa }, byte{ 0xfb }, byte{ 0x43 }, byte{ 0x4d }, byte{ 0x33 }, byte{ 0x85 }, byte{ 0x45 }, byte{ 0xf9 }, byte{ 0x02 }, byte{ 0x7f }, byte{ 0x50 }, byte{ 0x3c }, byte{ 0x9f }, byte{ 0xa8 }, byte{ 0x51 }, byte{ 0xa3 }, byte{ 0x40 }, byte{ 0x8f }, byte{ 0x92 }, byte{ 0x9d }, byte{ 0x38 }, byte{ 0xf5 }, byte{ 0xbc }, byte{ 0xb6 }, byte{ 0xda }, byte{ 0x21 }, byte{ 0x10 }, byte{ 0xff }, byte{ 0xf3 }, byte{ 0xd2 }, byte{ 0xcd }, byte{ 0x0c }, byte{ 0x13 }, byte{ 0xec }, byte{ 0x5f }, byte{ 0x97 }, byte{ 0x44 }, byte{ 0x17 }, byte{ 0xc4 }, byte{ 0xa7 }, byte{ 0x7e }, byte{ 0x3d }, byte{ 0x64 }, byte{ 0x5d }, byte{ 0x19 }, byte{ 0x73 }, byte{ 0x60 }, byte{ 0x81 }, byte{ 0x4f }, byte{ 0xdc }, byte{ 0x22 }, byte{ 0x2a }, byte{ 0x90 }, byte{ 0x88 }, byte{ 0x46 }, byte{ 0xee }, byte{ 0xb8 }, byte{ 0x14 }, byte{ 0xde }, byte{ 0x5e }, byte{ 0x0b }, byte{ 0xdb }, byte{ 0xe0 }, byte{ 0x32 }, byte{ 0x3a }, byte{ 0x0a }, byte{ 0x49 }, byte{ 0x06 }, byte{ 0x24 }, byte{ 0x5c }, byte{ 0xc2 }, byte{ 0xd3 }, byte{ 0xac }, byte{ 0x62 }, byte{ 0x91 }, byte{ 0x95 }, byte{ 0xe4 }, byte{ 0x79 }, byte{ 0xe7 }, byte{ 0xc8 }, byte{ 0x37 }, byte{ 0x6d }, byte{ 0x8d }, byte{ 0xd5 }, byte{ 0x4e }, byte{ 0xa9 }, byte{ 0x6c }, byte{ 0x56 }, byte{ 0xf4 }, byte{ 0xea }, byte{ 0x65 }, byte{ 0x7a }, byte{ 0xae }, byte{ 0x08 }, byte{ 0xba }, byte{ 0x78 }, byte{ 0x25 }, byte{ 0x2e }, byte{ 0x1c }, byte{ 0xa6 }, byte{ 0xb4 }, byte{ 0xc6 }, byte{ 0xe8 }, byte{ 0xdd }, byte{ 0x74 }, byte{ 0x1f }, byte{ 0x4b }, byte{ 0xbd }, byte{ 0x8b }, byte{ 0x8a }, byte{ 0x70 }, byte{ 0x3e }, byte{ 0xb5 }, byte{ 0x66 }, byte{ 0x48 }, byte{ 0x03 }, byte{ 0xf6 }, byte{ 0x0e }, byte{ 0x61 }, byte{ 0x35 }, byte{ 0x57 }, byte{ 0xb9 }, byte{ 0x86 }, byte{ 0xc1 }, byte{ 0x1d }, byte{ 0x9e }, byte{ 0xe1 }, byte{ 0xf8 }, byte{ 0x98 }, byte{ 0x11 }, byte{ 0x69 }, byte{ 0xd9 }, byte{ 0x8e }, byte{ 0x94 }, byte{ 0x9b }, byte{ 0x1e }, byte{ 0x87 }, byte{ 0xe9 }, byte{ 0xce }, byte{ 0x55 }, byte{ 0x28 }, byte{ 0xdf }, byte{ 0x8c }, byte{ 0xa1 }, byte{ 0x89 }, byte{ 0x0d }, byte{ 0xbf }, byte{ 0xe6 }, byte{ 0x42 }, byte{ 0x68 }, byte{ 0x41 }, byte{ 0x99 }, byte{ 0x2d }, byte{ 0x0f }, byte{ 0xb0 }, byte{ 0x54 }, byte{ 0xbb }, byte{ 0x16 } };
byte inv_sbox[256] = { byte{ 0x52 }, byte{ 0x09 }, byte{ 0x6a }, byte{ 0xd5 }, byte{ 0x30 }, byte{ 0x36 }, byte{ 0xa5 }, byte{ 0x38 }, byte{ 0xbf }, byte{ 0x40 }, byte{ 0xa3 }, byte{ 0x9e }, byte{ 0x81 }, byte{ 0xf3 }, byte{ 0xd7 }, byte{ 0xfb },byte{ 0x7c }, byte{ 0xe3 }, byte{ 0x39 }, byte{ 0x82 }, byte{ 0x9b }, byte{ 0x2f }, byte{ 0xff }, byte{ 0x87 }, byte{ 0x34 }, byte{ 0x8e }, byte{ 0x43 }, byte{ 0x44 }, byte{ 0xc4 }, byte{ 0xde }, byte{ 0xe9 }, byte{ 0xcb },byte{ 0x54 }, byte{ 0x7b }, byte{ 0x94 }, byte{ 0x32 }, byte{ 0xa6 }, byte{ 0xc2 }, byte{ 0x23 }, byte{ 0x3d }, byte{ 0xee }, byte{ 0x4c }, byte{ 0x95 }, byte{ 0x0b }, byte{ 0x42 }, byte{ 0xfa }, byte{ 0xc3 }, byte{ 0x4e },byte{ 0x08 }, byte{ 0x2e }, byte{ 0xa1 }, byte{ 0x66 }, byte{ 0x28 }, byte{ 0xd9 }, byte{ 0x24 }, byte{ 0xb2 }, byte{ 0x76 }, byte{ 0x5b }, byte{ 0xa2 }, byte{ 0x49 }, byte{ 0x6d }, byte{ 0x8b }, byte{ 0xd1 }, byte{ 0x25 },byte{ 0x72 }, byte{ 0xf8 }, byte{ 0xf6 }, byte{ 0x64 }, byte{ 0x86 }, byte{ 0x68 }, byte{ 0x98 }, byte{ 0x16 }, byte{ 0xd4 }, byte{ 0xa4 }, byte{ 0x5c }, byte{ 0xcc }, byte{ 0x5d }, byte{ 0x65 }, byte{ 0xb6 }, byte{ 0x92 },byte{ 0x6c }, byte{ 0x70 }, byte{ 0x48 }, byte{ 0x50 }, byte{ 0xfd }, byte{ 0xed }, byte{ 0xb9 }, byte{ 0xda }, byte{ 0x5e }, byte{ 0x15 }, byte{ 0x46 }, byte{ 0x57 }, byte{ 0xa7 }, byte{ 0x8d }, byte{ 0x9d }, byte{ 0x84 },byte{ 0x90 }, byte{ 0xd8 }, byte{ 0xab }, byte{ 0x00 }, byte{ 0x8c }, byte{ 0xbc }, byte{ 0xd3 }, byte{ 0x0a }, byte{ 0xf7 }, byte{ 0xe4 }, byte{ 0x58 }, byte{ 0x05 }, byte{ 0xb8 }, byte{ 0xb3 }, byte{ 0x45 }, byte{ 0x06 },byte{ 0xd0 }, byte{ 0x2c }, byte{ 0x1e }, byte{ 0x8f }, byte{ 0xca }, byte{ 0x3f }, byte{ 0x0f }, byte{ 0x02 }, byte{ 0xc1 }, byte{ 0xaf }, byte{ 0xbd }, byte{ 0x03 }, byte{ 0x01 }, byte{ 0x13 }, byte{ 0x8a }, byte{ 0x6b },byte{ 0x3a }, byte{ 0x91 }, byte{ 0x11 }, byte{ 0x41 }, byte{ 0x4f }, byte{ 0x67 }, byte{ 0xdc }, byte{ 0xea }, byte{ 0x97 }, byte{ 0xf2 }, byte{ 0xcf }, byte{ 0xce }, byte{ 0xf0 }, byte{ 0xb4 }, byte{ 0xe6 }, byte{ 0x73 },byte{ 0x96 }, byte{ 0xac }, byte{ 0x74 }, byte{ 0x22 }, byte{ 0xe7 }, byte{ 0xad }, byte{ 0x35 }, byte{ 0x85 }, byte{ 0xe2 }, byte{ 0xf9 }, byte{ 0x37 }, byte{ 0xe8 }, byte{ 0x1c }, byte{ 0x75 }, byte{ 0xdf }, byte{ 0x6e },byte{ 0x47 }, byte{ 0xf1 }, byte{ 0x1a }, byte{ 0x71 }, byte{ 0x1d }, byte{ 0x29 }, byte{ 0xc5 }, byte{ 0x89 }, byte{ 0x6f }, byte{ 0xb7 }, byte{ 0x62 }, byte{ 0x0e }, byte{ 0xaa }, byte{ 0x18 }, byte{ 0xbe }, byte{ 0x1b },byte{ 0xfc }, byte{ 0x56 }, byte{ 0x3e }, byte{ 0x4b }, byte{ 0xc6 }, byte{ 0xd2 }, byte{ 0x79 }, byte{ 0x20 }, byte{ 0x9a }, byte{ 0xdb }, byte{ 0xc0 }, byte{ 0xfe }, byte{ 0x78 }, byte{ 0xcd }, byte{ 0x5a }, byte{ 0xf4 },byte{ 0x1f }, byte{ 0xdd }, byte{ 0xa8 }, byte{ 0x33 }, byte{ 0x88 }, byte{ 0x07 }, byte{ 0xc7 }, byte{ 0x31 }, byte{ 0xb1 }, byte{ 0x12 }, byte{ 0x10 }, byte{ 0x59 }, byte{ 0x27 }, byte{ 0x80 }, byte{ 0xec }, byte{ 0x5f },byte{ 0x60 }, byte{ 0x51 }, byte{ 0x7f }, byte{ 0xa9 }, byte{ 0x19 }, byte{ 0xb5 }, byte{ 0x4a }, byte{ 0x0d }, byte{ 0x2d }, byte{ 0xe5 }, byte{ 0x7a }, byte{ 0x9f }, byte{ 0x93 }, byte{ 0xc9 }, byte{ 0x9c }, byte{ 0xef },byte{ 0xa0 }, byte{ 0xe0 }, byte{ 0x3b }, byte{ 0x4d }, byte{ 0xae }, byte{ 0x2a }, byte{ 0xf5 }, byte{ 0xb0 }, byte{ 0xc8 }, byte{ 0xeb }, byte{ 0xbb }, byte{ 0x3c }, byte{ 0x83 }, byte{ 0x53 }, byte{ 0x99 }, byte{ 0x61 },byte{ 0x17 }, byte{ 0x2b }, byte{ 0x04 }, byte{ 0x7e }, byte{ 0xba }, byte{ 0x77 }, byte{ 0xd6 }, byte{ 0x26 }, byte{ 0xe1 }, byte{ 0x69 }, byte{ 0x14 }, byte{ 0x63 }, byte{ 0x55 }, byte{ 0x21 }, byte{ 0x0c }, byte{ 0x7d } };

struct state {
	byte stateByte[4][4];
};


byte SubBytes(byte a) {
	byte temp = sbox[to_integer<int>(a)];
	return temp;
}

byte InvSubBytes(byte a) {
	byte temp = inv_sbox[to_integer<int>(a)];
	return temp;
}

struct state ShiftRow(struct state s) {
	struct state temp;
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			if (i == 0) {
				temp.stateByte[i][j] = s.stateByte[i][j];
			}
			if (i == 1) {
				temp.stateByte[i][j] = s.stateByte[i][((j + 1) % 4)];
			}
			if (i == 2) {
				temp.stateByte[i][j] = s.stateByte[i][((j + 2) % 4)];
			}
			if (i == 3) {
				temp.stateByte[i][j] = s.stateByte[i][((j + 3) % 4)];
			}

		}
	}
	return temp;
}

//xtime function for left shifting the input
byte xtime(byte variable)
{
	//if it is 0x02, check the highest order bit for overflow
	if ((variable >> 7) == byte{ 0x01 })
		return ((variable << 1) ^ byte { 0x1b });
	else
		return ((variable << 1) ^ byte { 0x00 });
}

//used in MixColumns and in the future inverse MixColumns to multiply a byte with one of the constants
byte mixMultiply(byte variable, byte constant)
{
	//check which constant is being multiplied
	if (constant == byte{ 0x02 })
	{
		//if it is 0x02, check the highest order bit for overflow
		if ((variable >> 7) == byte{ 0x01 })
			return ((variable << 1) ^ byte { 0x1b });
		else
			return ((variable << 1) ^ byte { 0x00 });
	}
	else if (constant == byte{ 0x03 })
	{
		//in the case of 0x03 we call again for 0x02 and the variable value, before XORing with its original value
		return mixMultiply(variable, byte{ 0x02 }) ^ variable;
	}
	else if(constant == byte{ 0x09 })
	{
		//in the case of 0x09, we turn it into 0x08 + 0x01
		return mixMultiply(mixMultiply(mixMultiply(variable, byte{ 0x02 }), byte{ 0x02 }), byte{ 0x02 }) ^ variable;
	}
	else if (constant == byte{ 0x0b })
	{
		//in the case of 0x0b, we turn it into 0x08 + 0x02 + 0x01
		return mixMultiply(mixMultiply(mixMultiply(variable, byte{ 0x02 }), byte{ 0x02 }), byte{ 0x02 }) ^ mixMultiply(variable, byte{ 0x02 }) ^ variable;
	}
	else if (constant == byte{ 0x0d })
	{
		//in the case of 0x0d, we turn it into 0x08 + 0x04 + 0x01
		return mixMultiply(mixMultiply(mixMultiply(variable, byte{ 0x02 }), byte{ 0x02 }), byte{ 0x02 }) ^ mixMultiply(mixMultiply(variable, byte{ 0x02 }), byte{ 0x02 }) ^ variable;
	}
	else if (constant == byte{ 0x0e })
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

		//
		s.stateByte[0][column] = (mixMultiply(s0c, byte{0x02})) ^ (mixMultiply(s1c, byte{ 0x03 })) ^ s2c ^ s3c;

		//
		s.stateByte[1][column] = s0c ^ (mixMultiply(s1c, byte{ 0x02 })) ^ (mixMultiply(s2c, byte{ 0x03 })) ^ s3c;

		//
		s.stateByte[2][column] = s0c ^ s1c ^ (mixMultiply(s2c, byte{ 0x02 })) ^ (mixMultiply(s3c, byte{ 0x03 }));

		//
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

		//
		s.stateByte[0][column] = (mixMultiply(s0c, byte{ 0x0e })) ^ (mixMultiply(s1c, byte{ 0x0b })) ^ (mixMultiply(s2c, byte{ 0x0d })) ^ (mixMultiply(s3c, byte{ 0x09 }));

		//
		s.stateByte[1][column] = (mixMultiply(s0c, byte{ 0x09 })) ^ (mixMultiply(s1c, byte{ 0x0e })) ^ (mixMultiply(s2c, byte{ 0x0b })) ^ (mixMultiply(s3c, byte{ 0x0d }));

		//
		s.stateByte[2][column] = (mixMultiply(s0c, byte{ 0x0d })) ^ (mixMultiply(s1c, byte{ 0x09 })) ^ (mixMultiply(s2c, byte{ 0x0e })) ^ (mixMultiply(s3c, byte{ 0x0b }));

		//
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
			else if(formatFlag == 'i')
				cout << dec << to_integer<int>(s.stateByte[i][j]) << "\t";
		}
		cout << "\n";
	}
}

int main()
{
	/*
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
	*/
	
	//input 16 characters as test
	string input = "";
	getline(cin, input);
	

	//take user input and store it in an initial state array
	struct state s;
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			s.stateByte[i][j] = (byte)input.at(4*j + i);
		}
	}
	PrintState(s, 'h');

	//SUB BYTES
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			s.stateByte[i][j] = SubBytes(s.stateByte[i][j]);
		}
	}
	cout << "\nstate after sub bytes\n";
	PrintState(s, 'h');

	//SHIFT ROWS 
	s = ShiftRow(s);
	cout << "\n\nstate after shift row\n";
	PrintState(s, 'h');

	//MIX COLUMNS
	s = MixColumns(s);
	cout << "\n\nstate after mix column\n";
	PrintState(s, 'h');
	

	//Testing of inverse mix multiplications
	//cout << hex << to_integer<int>(mixMultiply(byte{ 0x57 }, byte{ 0x09 }));

	string pause = "";
	getline(cin, pause);
	return 0;
}
