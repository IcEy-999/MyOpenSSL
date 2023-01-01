#include<Windows.h>
#include<iostream>
//加密时用到的64个常量 自然数中取前64个质数 的立方根小数部分 取前32bit 
ULONG32 K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
//8个hash初始值 自然数中前8个质数 的平方根小数部分 取前32bit
ULONG32 h0[8] = { 0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19 };
//基本算法 ，hash时要用到：
ULONG32 MyMemlen_Bit(PUCHAR M) {
    int j = 0;
    while (M[j++] != 0x0);
    return (j - 1) * 8;
}

ULONG32 SL(ULONG32 x, int n) {//左循环n位
    ULONG32 y = x << n;
    x = x >> (32 - n);
    return x | y;
}

ULONG32 SR(ULONG32 x, int n) {//右循环n位
    ULONG32 y = x >> n;
    x = x << (32 - n);
    return x | y;

}

ULONG32 Ch(ULONG32 x, ULONG32 y, ULONG32 z) {
    return (x & y) ^ (~x & z);
}

ULONG32 Maj(ULONG32 x, ULONG32 y, ULONG32 z) {
    return ((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z));
}

ULONG32 Ep0(ULONG32 x) {
    return SR(x, 2) ^ SR(x, 13) ^ SR(x, 22);
}

ULONG32 Ep1(ULONG32 x) {
    return SR(x, 6) ^ SR(x, 11) ^ SR(x, 25);
}

ULONG32 SIG0(ULONG32 x) {
    return SR(x, 7) ^ SR(x, 18) ^ ((x) >> 3);
}

ULONG32 SIG1(ULONG32 x) {
    return SR(x, 17) ^ SR(x, 19) ^ ((x) >> 10);
}

//端序转换
VOID C_T_S(PULONG32 X) {
    ULONG32 ls = 0;
    PUCHAR X_p = (PUCHAR)X;
    PUCHAR ls_p = (PUCHAR)&ls;
    for (int i = 0; i < 4; i++) {
        ls_p[i] = X_p[3 - i];
    }
    *X = ls;
    return;
}

typedef struct _SHA256_Data {
    PUCHAR M;
    ULONG32 M_Len_Bit;
    PUCHAR Mc;
    ULONG32 Mc_Len_Bit;

    ULONG32(*nW)[64];

    PUCHAR Hash_Data;
    _SHA256_Data(PUCHAR M);
}SHA256_Data, * PSHA256_Data;

SHA256_Data::_SHA256_Data(PUCHAR M) {
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
    ULONG64 bl_f = 0;
    PUCHAR blp = (PUCHAR)&bl;
    PUCHAR bl_fp = (PUCHAR)&bl_f;
    for (int i = 0; i < 8; i++)
        bl_fp[i] = blp[7 - i];


    memcpy(&buffer[(Len_bf + 8) / 8], bl_fp, 8);
    this->Mc = buffer;
    this->Mc_Len_Bit = pout;
    this->M = M_buffer;
    this->Hash_Data = (PUCHAR)malloc(32);
    //this->H = (ULONG32 (*)[8])malloc(((Mc_Len_Bit/512)+1)*8*4);
}

BOOLEAN SHA256_HASH(PSHA256_Data Data) {
    ULONG32 R[8] = { 0 };
    ULONG32 A = R[0], B = R[1], C = R[2], D = R[3], E = R[4], F = R[5], G = R[6], H = R[7];
    ULONG32 T1 = 0, T2 = 0;//零时变量
    ULONG32 Ac = 0, Bc = 0, Cc = 0, Dc = 0, Ec = 0, Fc = 0, Gc = 0, Hc = 0;//端序转换
    int B_i = Data->Mc_Len_Bit / 512;
    ULONG32(*nH)[8] = (ULONG32(*)[8])malloc((B_i + 1) * 8 * 4);
    memcpy(&nH[0][0], h0, 32);
    UCHAR T_buffer[32] = { 0 };
    for (int i = 0; i < B_i; i++) {
        memcpy(T_buffer, &nH[i][0], 32);
        /*for (int k = 0; k < 8; k++)
            R[k] = ((ULONG32)T_buffer[k * 4]) << 24 | ((ULONG32)T_buffer[k * 4 + 1]) << 16 | ((ULONG32)T_buffer[k * 4 + 2]) << 8 | ((ULONG32)T_buffer[k * 4 + 3]);
        A = R[0]; B = R[1]; C = R[2]; D = R[3]; E = R[4]; F = R[5]; G = R[6]; H = R[7];*/
        A = nH[i][0];B = nH[i][1];C= nH[i][2];D= nH[i][3];E= nH[i][4];F= nH[i][5];G= nH[i][6];H= nH[i][7];
        for (int j = 0; j < 64; j++) {
            T1 = H + Ep1(E) + Ch(E, F, G) + K[j] + Data->nW[i][j];
            T2 = Ep0(A) + Maj(A, B, C);
            H = G;
            G = F;
            F = E;
            E = D + T1;
            D = C;
            C = B;
            B = A;
            A = T1 + T2;
        }
        nH[i + 1][0] = A + nH[i][0];
        nH[i + 1][1] = B + nH[i][1];
        nH[i + 1][2] = C + nH[i][2];
        nH[i + 1][3] = D + nH[i][3];
        nH[i + 1][4] = E + nH[i][4];
        nH[i + 1][5] = F + nH[i][5];
        nH[i + 1][6] = G + nH[i][6];
        nH[i + 1][7] = H + nH[i][7];
    }
    memcpy(Data->Hash_Data, &nH[B_i][0], 32);
    for (int i = 0; i < 8; i++)
    {
        C_T_S((PULONG32)(Data->Hash_Data + (i * 4)));
    }
    return TRUE;


}

BOOLEAN Mc_To_W(PSHA256_Data Data) {
    int B_i = Data->Mc_Len_Bit / 512;
    ULONG32(*nW)[64] = (ULONG32(*)[64])malloc(B_i * 64 * 4);//每个512bit块64个W
    for (int i = 0; i < B_i; i++) {
        for (int j = 0; j < 16; j++) {//初始化 Bi(W0 - w15)
            nW[i][j] = (ULONG32)(Data->Mc[i * 512 / 8 + j * 4] << 24 | Data->Mc[i * 512 / 8 + j * 4 + 1] << 16 | Data->Mc[i * 512 / 8 + j * 4 + 2] << 8 | Data->Mc[i * 512 / 8 + j * 4 + 3]);
        }

        for (int j = 16; j < 64; j++) {//初始化 Bi(W16 - W67)
            nW[i][j] = SIG1(nW[i][j - 2]) + nW[i][j - 7] + SIG0(nW[i][j - 15]) + nW[i][j - 16];
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
    SHA256_Data test(hx);
    Mc_To_W(&test);
    SHA256_HASH(&test);
    printf("消息：%s\nSHA256 Hash结果:\n", hx);
    dumpbuf(test.Hash_Data, 32);
    system("pause");
}