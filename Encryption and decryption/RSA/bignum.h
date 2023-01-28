#pragma once
#pragma once
#include<Windows.h>
#include<iostream>
#define Bit_Wide 4096 //¶àÉÙÎ»


class bignum {
public:
	union
	{
		ULONG64 U64[Bit_Wide / 64 * 2 + 1];
		ULONG32 U32[Bit_Wide / 32 * 2 + 2];
	};
	ULONG32 U64_Len;//used ULONG64 number
	bignum();
	//set number = 0
	VOID clear();
	//print number (hexadecimal)
	VOID out();
	VOID set_len();
	//set number,Only hexadecimal is supported "0x???"
	BOOLEAN set(const char* number);
};


class bignum_div_r {
public:
	bignum div, mod;
};


/*
	cmp a, b
	return 1:a > b;
	return 0:a < b;
	return 2:a = b;
*/
UCHAR bignum_cmp(bignum a, bignum b);
//a << n
bignum bignum_ls(bignum a, ULONG64 n);
//a >> n
bignum bignum_rs(bignum a, ULONG64 n);
//a + b
bignum bignum_add(bignum a, bignum b);
//a - b
bignum bignum_sub(bignum a, bignum b);
//a * b
bignum bignum_imul(bignum a, bignum b);
//a / b
bignum bignum_div(bignum a, bignum b);
//a % b
bignum bignum_mod(bignum a, bignum b);
//a & b
bignum bignum_and(bignum a, bignum b);
//a | b
bignum bignum_or(bignum a, bignum b);
//a ^ b
bignum bignum_xor(bignum a, bignum b);
//~a
bignum bignum_not(bignum a);
//pow(a,b)
bignum bignum_pow(bignum a, bignum b);

//return a/b and a%b
bignum_div_r bignum_div_all(bignum a, bignum b);