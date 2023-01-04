#include<iostream>
#include<Windows.h>
//#include<Windows.h>

//加密时用到的64个常量 
ULONG32 K[] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};
//4个hash初始值 
ULONG32 h0[] = {
    0x67452301,0xefcdab89,0x98badcfe,0x10325476
};

ULONG32 r[] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};


ULONG32 MyMemlen_Bit(PUCHAR M) {
    int j = 0;
    while (M[j++] != 0x0);
    return (j - 1) * 8;
}
//基本算法 ，hash时要用到：
ULONG32 SL(ULONG32 x, int n) {//左循环n位
    ULONG32 y = x << n;
    x = x >> (32 - n);
    return x | y;
}

typedef struct _MD5_Data {
    PUCHAR M;
    ULONG32 M_Len_Bit;
    PUCHAR Mc;
    ULONG32 Mc_Len_Bit;

    ULONG32(*nW)[16];

    PUCHAR Hash_Data;
    _MD5_Data(PUCHAR M);
}MD5_Data, * PMD5_Data;

MD5_Data::_MD5_Data(PUCHAR M) {
    this->M_Len_Bit = MyMemlen_Bit(M);
    ULONG32 Len_bf = this->M_Len_Bit;
    ULONG64 bl = 0;
    int mod = this->M_Len_Bit % 512;
    if (mod + 64 + 8 <= 512 && mod > 0) {
        while ((Len_bf + 64 + 8) % 512 != 0) {//留一个8bit and 64bit整数
            Len_bf += 8;
        }
    }
    else {
        while ((Len_bf) % 512 != 0) {//补长度，512
            Len_bf += 8;
        }
        Len_bf += 8;
        while ((Len_bf + 64 + 8) % 512 != 0) {//留一个8bit and 64bit整数
            Len_bf += 8;
        }
    }
    ULONG32 pout = Len_bf + 64 + 8;
    PUCHAR buffer = (PUCHAR)malloc((Len_bf + 8 + 64) / 8);
    PUCHAR M_buffer = (PUCHAR)malloc((this->M_Len_Bit) / 8);
    memset(buffer, 0, (Len_bf + 8 + 64) / 8);
    memcpy(buffer, M, this->M_Len_Bit / 8);
    memcpy(M_buffer, M, (this->M_Len_Bit / 8));
    buffer[this->M_Len_Bit / 8] = 1 << 7;
    bl = this->M_Len_Bit;
    ULONG64 bl_f = bl;
    memcpy(&buffer[(Len_bf + 8) / 8], &bl_f, 8);
    this->Mc = buffer;
    this->Mc_Len_Bit = pout;
    this->M = M_buffer;
    this->Hash_Data = (PUCHAR)malloc(32);
}

BOOLEAN MD5_HASH(PMD5_Data Data) {
    ULONG32 A = 0, B = 0, C = 0, D = 0,  F = 0, G = 0;
    ULONG32 T1 = 0;//临时变量
    ULONG32 B_i = Data->Mc_Len_Bit / 512;
    ULONG32(*nH)[4] = (ULONG32(*)[4])malloc((B_i + 1) * 4 * 4);
    memcpy(&nH[0][0], h0, 16);
    for (ULONG32 i = 0; i < B_i; i++) {
        A = nH[i][0]; B = nH[i][1]; C = nH[i][2]; D = nH[i][3];
        for (ULONG32 j = 0; j < 64; j++) {
            if (j < 16) {
                F = (B & C) | (~B & D);
                G = j;
            }
            else if (j < 32) {
                F = (D & B) | (~D & C);
                G = (5 * j + 1) % 16;
            }
            else if (j < 48) {
                F = B ^ C ^ D;
                G = (3 * j + 5) % 16;
            }
            else {
                F = C ^ (B | ~D);
                G = (7 * j) % 16;
            }
            T1 = D;
            D = C;
            C = B;
            B = B + SL((A + F + K[j] + Data->nW[i][G]), r[j]);
            A = T1;
        }
        nH[i + 1][0] = A + nH[i][0];
        nH[i + 1][1] = B + nH[i][1];
        nH[i + 1][2] = C + nH[i][2];
        nH[i + 1][3] = D + nH[i][3];
        //nH[i + 1][4] = E + nH[i][4];
    }
    memcpy(Data->Hash_Data, &nH[B_i][0], 32);
    return TRUE;


}

BOOLEAN Mc_To_W(PMD5_Data Data) {
    int B_i = Data->Mc_Len_Bit / 512;
    ULONG32(*nW)[16] = (ULONG32(*)[16])malloc(B_i * 16 * 4);//每个512bit块16个W
    for (int i = 0; i < B_i; i++) {
        for (int j = 0; j < 16; j++) {//初始化 Bi(W0 - w15)
            nW[i][j] = *(PULONG32)&Data->Mc[i * 512 / 8 + j * 4];
        }
    }
    Data->nW = nW;
    return 1;
}

VOID dumpbuf(unsigned char* buf, int len)
{
    int i;
    for (i = 0; i < len; i++) {
        printf("%02x ", buf[i]);
        if (i > 0 && (1 + i) % 16 == 0)
            putchar('\n');
    }
    return;
}

int main() {
    UCHAR hx[] = "aaaaaaaaaa";
    MD5_Data test(hx);
    Mc_To_W(&test);
    MD5_HASH(&test);
    printf("消息：%s\nMD5 Hash结果:\n", hx);
    dumpbuf(test.Hash_Data, 16);
    printf("\n");
    system("pause");
}