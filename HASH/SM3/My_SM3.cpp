#include<Windows.h>
#include<iostream>
ULONG32 vv[] = { 0x7380166f,0x4914b2b9,0x172442d7,0xda8a0600,0xa96f30bc,0x163138aa,0xe38dee4d, 0xb0fb0e4e };

ULONG32 SL(ULONG32 X, int n)
{
    unsigned __int64 x = X;
    x = x << (n % 32);
    unsigned long l = (unsigned long)(x >> 32);
    return x | l;
}

ULONG32 MyMemlen_Bit(PUCHAR M) {
    int j = 0;
    while (M[j++] != 0x0);
    return (j - 1) * 8;
}

ULONG32 Tj(int j) {
    if (j >= 0 && j <= 15)
        return 0x79cc4519;
    else
        return 0x7a879d8a;
}

ULONG32 FFj(int j, ULONG32 X, ULONG32 Y, ULONG32 Z) {
    if (j >= 0 && j <= 15)
        return X ^ Y ^ Z;
    else
        return ((X & Y) | (X & Z) | (Y & Z));
}

ULONG32 GGj(int j, ULONG32 X, ULONG32 Y, ULONG32 Z) {
    if (j >= 0 && j <= 15)
        return X ^ Y ^ Z;
    else
        return ((X & Y) | (~X & Z));

}

ULONG32 P0(ULONG32 X) {
    return X ^ SL(X, 9) ^ SL(X, 17);
}

ULONG32 P1(ULONG32 X) {
    return X ^ SL(X, 15) ^ SL(X, 23);
}

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

typedef struct _Sm3_Data
{
    PUCHAR M;
    ULONG32 M_Len_Bit;
    PUCHAR Mc;
    ULONG32 Mc_Len_Bit;
    ULONG32(*nW)[68];
    ULONG32(*nWc)[64];
    PUCHAR Hash_Data;
    _Sm3_Data(PUCHAR M);
}Sm3_Data, * PSm3_Data;

Sm3_Data::_Sm3_Data(PUCHAR M) {
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
}

BOOLEAN Sm3_Hash(PSm3_Data Data) {
    ULONG32 A = 0, B = 0, C = 0, D = 0, E = 0, F = 0, G = 0, H = 0;
    int B_i = Data->Mc_Len_Bit / 512;
    ULONG32(*V)[8] = (ULONG32(*)[8])malloc((B_i + 1) * 4 * 8);
    memcpy(&V[0][0], &vv[0], 32);
    ULONG32 SS1 = 0, SS2 = 0, TT1 = 0, TT2 = 0;
    UCHAR T_buffer[32] = { 0 };
    for (int i = 0; i < B_i; i++) {
        A = V[i][0]; B = V[i][1]; C = V[i][2]; D = V[i][3]; E = V[i][4]; F = V[i][5]; G = V[i][6]; H = V[i][7];
        for (int j = 0; j < 64; j++) {
            SS1 = SL(SL(A, 12) + E + SL(Tj(j), j), 7);
            SS2 = SS1 ^ SL(A, 12);
            TT1 = FFj(j, A, B, C) + D + SS2 + Data->nWc[i][j];
            TT2 = GGj(j, E, F, G) + H + SS1 + Data->nW[i][j];
            D = C;
            C = SL(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = SL(F, 19);
            F = E;
            E = P0(TT2);
        }
        V[i + 1][0] = A ^ V[i][0];
        V[i + 1][1] = B ^ V[i][1];
        V[i + 1][2] = C ^ V[i][2];
        V[i + 1][3] = D ^ V[i][3];
        V[i + 1][4] = E ^ V[i][4];
        V[i + 1][5] = F ^ V[i][5];
        V[i + 1][6] = G ^ V[i][6];
        V[i + 1][7] = H ^ V[i][7];

    }

    memcpy(Data->Hash_Data, &V[B_i][0], 32);
    for (int i = 0; i < 8; i++)
    {
        C_T_S((PULONG32)(Data->Hash_Data + (i * 4)));
    }
    return 1;
}

BOOLEAN Mc_To_WWc(PSm3_Data Data) {
    int B_i = Data->Mc_Len_Bit / 512;
    ULONG32(*nW)[68] = (ULONG32(*)[68])malloc(B_i * 68 * 4);//每个B，68个W    W
    ULONG32(*nWc)[64] = (ULONG32(*)[64])malloc(B_i * 64 * 4);//每个B，64个Wc  W'
    for (int i = 0; i < B_i; i++) {
        for (int j = 0; j < 16; j++) {//初始化 Bi(W0 - w15)
            nW[i][j] = (ULONG32)(Data->Mc[i * 512 / 8 + j * 4] << 24 | Data->Mc[i * 512 / 8 + j * 4 + 1] << 16 | Data->Mc[i * 512 / 8 + j * 4 + 2] << 8 | Data->Mc[i * 512 / 8 + j * 4 + 3]);
        }

        for (int j = 16; j < 68; j++) {//初始化 Bi(W16 - W67)
            nW[i][j] = P1(nW[i][j - 16] ^ nW[i][j - 9] ^ SL(nW[i][j - 3], 15)) ^ SL(nW[i][j - 13], 7) ^ nW[i][j - 6];
        }

        for (int j = 0; j < 64; j++) {//初始化 Bi(W'0 - W'63)
            nWc[i][j] = nW[i][j] ^ nW[i][j + 4];
        }
    }
    Data->nW = nW;
    Data->nWc = nWc;
    return 1;
}

VOID dumpbuf(unsigned char* buf, int len)
{
    int i, line = 32;
    for (i = 0; i < len; i++) {
        printf("%02x ", buf[i]);
        if (i > 0 && (1 + i) % 16 == 0)
            putchar('\n');
    }
    return;
}

int main() {
    UCHAR hx[] = "123";
    Sm3_Data test(hx);
    Mc_To_WWc(&test);
    Sm3_Hash(&test);
    printf("消息：%s\nSM3 Hash结果:\n", hx);
    dumpbuf(test.Hash_Data, 32);
    system("pause");

}