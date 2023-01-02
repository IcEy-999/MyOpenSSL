#include<iostream>
#include<Windows.h>

//阉割版：正常SHA512 可散列2^128 Bit长的数据 ， 这个只可散列 2^64 Bit长的数据
//80个初始常量
ULONG64 K[] = {
    0x428A2F98D728AE22ULL,  0x7137449123EF65CDULL, 0xB5C0FBCFEC4D3B2FULL,  0xE9B5DBA58189DBBCULL,
    0x3956C25BF348B538ULL,  0x59F111F1B605D019ULL, 0x923F82A4AF194F9BULL,  0xAB1C5ED5DA6D8118ULL,
    0xD807AA98A3030242ULL,  0x12835B0145706FBEULL, 0x243185BE4EE4B28CULL,  0x550C7DC3D5FFB4E2ULL,
    0x72BE5D74F27B896FULL,  0x80DEB1FE3B1696B1ULL, 0x9BDC06A725C71235ULL,  0xC19BF174CF692694ULL,
    0xE49B69C19EF14AD2ULL,  0xEFBE4786384F25E3ULL, 0x0FC19DC68B8CD5B5ULL,  0x240CA1CC77AC9C65ULL,
    0x2DE92C6F592B0275ULL,  0x4A7484AA6EA6E483ULL, 0x5CB0A9DCBD41FBD4ULL,  0x76F988DA831153B5ULL,
    0x983E5152EE66DFABULL,  0xA831C66D2DB43210ULL, 0xB00327C898FB213FULL,  0xBF597FC7BEEF0EE4ULL,
    0xC6E00BF33DA88FC2ULL,  0xD5A79147930AA725ULL, 0x06CA6351E003826FULL,  0x142929670A0E6E70ULL,
    0x27B70A8546D22FFCULL,  0x2E1B21385C26C926ULL, 0x4D2C6DFC5AC42AEDULL,  0x53380D139D95B3DFULL,
    0x650A73548BAF63DEULL,  0x766A0ABB3C77B2A8ULL, 0x81C2C92E47EDAEE6ULL,  0x92722C851482353BULL,
    0xA2BFE8A14CF10364ULL,  0xA81A664BBC423001ULL, 0xC24B8B70D0F89791ULL,  0xC76C51A30654BE30ULL,
    0xD192E819D6EF5218ULL,  0xD69906245565A910ULL, 0xF40E35855771202AULL,  0x106AA07032BBD1B8ULL,
    0x19A4C116B8D2D0C8ULL,  0x1E376C085141AB53ULL, 0x2748774CDF8EEB99ULL,  0x34B0BCB5E19B48A8ULL,
    0x391C0CB3C5C95A63ULL,  0x4ED8AA4AE3418ACBULL, 0x5B9CCA4F7763E373ULL,  0x682E6FF3D6B2B8A3ULL,
    0x748F82EE5DEFB2FCULL,  0x78A5636F43172F60ULL, 0x84C87814A1F0AB72ULL,  0x8CC702081A6439ECULL,
    0x90BEFFFA23631E28ULL,  0xA4506CEBDE82BDE9ULL, 0xBEF9A3F7B2C67915ULL,  0xC67178F2E372532BULL,
    0xCA273ECEEA26619CULL,  0xD186B8C721C0C207ULL, 0xEADA7DD6CDE0EB1EULL,  0xF57D4F7FEE6ED178ULL,
    0x06F067AA72176FBAULL,  0x0A637DC5A2C898A6ULL, 0x113F9804BEF90DAEULL,  0x1B710B35131C471BULL,
    0x28DB77F523047D84ULL,  0x32CAAB7B40C72493ULL, 0x3C9EBE0A15C9BEBCULL,  0x431D67C49C100D4CULL,
    0x4CC5D4BECB3E42B6ULL,  0x597F299CFC657E2AULL, 0x5FCB6FAB3AD6FAECULL,  0x6C44198C4A475817ULL
};
//8个hash初始值 
ULONG64 h0[8] = {
    0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL,0x3C6EF372FE94F82BULL,0xA54FF53A5F1D36F1ULL,
    0x510E527FADE682D1ULL,0x9B05688C2B3E6C1FULL,0x1F83D9ABFB41BD6BULL,0x5BE0CD19137E2179ULL
};

ULONG64 MyMemlen_Bit(PUCHAR M) {
    int j = 0;
    while (M[j++] != 0x0);
    return (j - 1) * 8;
}
//基本算法 ，hash时要用到：
#define LSR(x,n) (x >> n)
#define ROR(x,n) (LSR(x,n) | (x << (64 - n)))
#define MA(x,y,z) ((x & y) | (z & (x | y)))
#define CH(x,y,z) (z ^ (x & (y ^ z)))
#define GAMMA0(x) (ROR(x, 1) ^ ROR(x, 8) ^  LSR(x, 7))
#define GAMMA1(x) (ROR(x,19) ^ ROR(x,61) ^  LSR(x, 6))
#define SIGMA0(x) (ROR(x,28) ^ ROR(x,34) ^ ROR(x,39))
#define SIGMA1(x) (ROR(x,14) ^ ROR(x,18) ^ ROR(x,41))

VOID C_T_S64(PULONG64 X) {
    ULONG64 ls = 0;
    PUCHAR X_p = (PUCHAR)X;
    PUCHAR ls_p = (PUCHAR)&ls;
    for (int i = 0; i < 8; i++) {
        ls_p[i] = X_p[7 - i];
    }
    *X = ls;
    return;
}

typedef struct _SHA512_Data {
    PUCHAR M;
    ULONG64 M_Len_Bit;
    PUCHAR Mc;
    ULONG64 Mc_Len_Bit;

    ULONG64(*nW)[80];

    PUCHAR Hash_Data;
    _SHA512_Data(PUCHAR M);
}SHA512_Data, * PSHA512_Data;


SHA512_Data::_SHA512_Data(PUCHAR M) {
    this->M_Len_Bit = MyMemlen_Bit(M);
    ULONG64 Len_bf = this->M_Len_Bit;
    ULONG64 bl = 0;
    int mod = this->M_Len_Bit % 1024;
    if (mod + 128 + 8 <= 1024 && mod > 0) {
        while ((Len_bf + 128 + 8) % 1024 != 0) {//留一个8bit and 64bit整数
            Len_bf += 8;
        }
    }
    else {
        while ((Len_bf) % 1024 != 0) {//补长度，512
            Len_bf += 8;
        }
        Len_bf += 8;
        while ((Len_bf + 128 + 8) % 1024 != 0) {//留一个8bit and 64bit整数
            Len_bf += 8;
        }
    }
    ULONG64 pout = Len_bf + 128 + 8;
    PUCHAR buffer = (PUCHAR)malloc((pout) / 8);
    PUCHAR M_buffer = (PUCHAR)malloc((this->M_Len_Bit) / 8);

    memset(buffer, 0, (pout) / 8);

    memcpy(buffer, M, this->M_Len_Bit / 8);
    memcpy(M_buffer, M, (this->M_Len_Bit / 8));
    buffer[this->M_Len_Bit / 8] = 1 << 7;
    bl = this->M_Len_Bit;
    ULONG64 bl_f = 0;
    PUCHAR blp = (PUCHAR)&bl;
    PUCHAR bl_fp = (PUCHAR)&bl_f;
    for (int i = 0; i < 8; i++)
        bl_fp[i] = blp[7 - i];


    memcpy(&buffer[(Len_bf + 8 + 64) / 8], bl_fp, 8);//原先SHA512 可以散列 2^128 长Bit的数据，但是我这里阉割了，变为和SHA512一样的2^64Bit长
    this->Mc = buffer;
    this->Mc_Len_Bit = pout;
    this->M = M_buffer;
    this->Hash_Data = (PUCHAR)malloc(64);
    this->nW = NULL;
}

BOOLEAN SHA256_HASH(PSHA512_Data Data) {
    ULONG64 R[8] = { 0 };
    ULONG64 A = R[0], B = R[1], C = R[2], D = R[3], E = R[4], F = R[5], G = R[6], H = R[7];
    ULONG64 T1 = 0, T2 = 0;//零时变量
    ULONG64 Ac = 0, Bc = 0, Cc = 0, Dc = 0, Ec = 0, Fc = 0, Gc = 0, Hc = 0;//端序转换
    ULONG64 B_i = Data->Mc_Len_Bit / 1024;
    ULONG64(*nH)[8] = (ULONG64(*)[8])malloc((B_i + 1) * 8 * 8);
    memcpy(&nH[0][0], h0, 64);
    for (ULONG64 i = 0; i < B_i; i++) {
        A = nH[i][0]; B = nH[i][1]; C = nH[i][2]; D = nH[i][3]; E = nH[i][4]; F = nH[i][5]; G = nH[i][6]; H = nH[i][7];
        for (ULONG64 j = 0; j < 80; j++) {
            T1 = H + SIGMA1(E) + CH(E, F, G) + K[j] + Data->nW[i][j];
            T2 = SIGMA0(A) + MA(A, B, C);
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
    memcpy(Data->Hash_Data, &nH[B_i][0], 64);
    for (int i = 0; i < 8; i++)
    {
        C_T_S64((PULONG64)(Data->Hash_Data + (i * 8)));
    }
    return TRUE;


}

BOOLEAN Mc_To_W(PSHA512_Data Data) {
    ULONG64 B_i = Data->Mc_Len_Bit / 1024;
    ULONG64(*nW)[80] = (ULONG64(*)[80])malloc(B_i * 80 * 8);//每个1024bit块80个W
    PULONG64 TransP = NULL;
    ULONG64 Trans = 0;
    for (ULONG64 i = 0; i < B_i; i++) {
        for (ULONG64 j = 0; j < 16; j++) {//初始化 Bi(W0 - w15)
            TransP = (PULONG64)Data->Mc;
            Trans = TransP[j];
            C_T_S64(&Trans);//端序转换
            nW[i][j] = Trans;
        }

        for (ULONG64 j = 16; j < 80; j++) {//初始化 Bi(W16 - W79)
            nW[i][j] = GAMMA1(nW[i][j - 2]) + nW[i][j - 7] + GAMMA0(nW[i][j - 15]) + nW[i][j - 16];
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
    SHA512_Data test(hx);
    Mc_To_W(&test);
    SHA256_HASH(&test);
    printf("消息：%s\nSHA512 Hash结果:\n", hx);
    dumpbuf(test.Hash_Data, 64);
    system("pause");
}