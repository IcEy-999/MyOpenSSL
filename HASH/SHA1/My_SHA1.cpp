#include<iostream>
#include<Windows.h>
//#include<Windows.h>

//加密时用到的4个常量 
ULONG32 K[] = {
    0x5A827999,0x6ED9EBA1,0x8F1BBCDC,0xCA62C1D6
};
//5个hash初始值 
ULONG32 h0[] = {
    0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0
};
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
ULONG32 Get_K(ULONG32 t) {
    if (t >= 0 && t <= 19)
        return K[0];
    else if (t >= 20 && t <= 39)
        return K[1];
    else if (t >= 40 && t <= 59)
        return K[2];
    else
        return K[3];
}

ULONG32 Ft(ULONG32 t, ULONG32 x, ULONG32 y, ULONG32 z) {
    if (t >= 0 && t <= 19)
        return (x & y) | (~x & z);
    else if (t >= 20 && t <= 39)
        return x ^ y ^ z;
    else if (t >= 40 && t <= 59)
        return (x & y) | (x & z) | (y & z);
    else
        return x ^ y ^ z;

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

typedef struct _SHA1_Data {
    PUCHAR M;
    ULONG32 M_Len_Bit;
    PUCHAR Mc;
    ULONG32 Mc_Len_Bit;

    ULONG32(*nW)[80];

    PUCHAR Hash_Data;
    _SHA1_Data(PUCHAR M);
}SHA1_Data, * PSHA1_Data;

SHA1_Data::_SHA1_Data(PUCHAR M) {
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

BOOLEAN SHA1_HASH(PSHA1_Data Data) {
    ULONG32 A = 0, B = 0, C = 0, D = 0, E = 0;
    ULONG32 T1 = 0;//临时变量
    ULONG32 B_i = Data->Mc_Len_Bit / 512;
    ULONG32(*nH)[5] = (ULONG32(*)[5])malloc((B_i + 1) * 5 * 4);
    memcpy(&nH[0][0], h0, 20);
    for (ULONG32 i = 0; i < B_i; i++) {
        A = nH[i][0]; B = nH[i][1]; C = nH[i][2]; D = nH[i][3]; E = nH[i][4];
        for (ULONG32 j = 0; j < 80; j++) {
            T1 = SL(A, 5) + Ft(j, B, C, D) + E + Data->nW[i][j] + Get_K(j);
            E = D;
            D = C;
            C = SL(B, 30);
            B = A;
            A = T1;
        }
        nH[i + 1][0] = A + nH[i][0];
        nH[i + 1][1] = B + nH[i][1];
        nH[i + 1][2] = C + nH[i][2];
        nH[i + 1][3] = D + nH[i][3];
        nH[i + 1][4] = E + nH[i][4];
    }
    memcpy(Data->Hash_Data, &nH[B_i][0], 32);
    for (int i = 0; i < 8; i++)
    {
        C_T_S((PULONG32)(Data->Hash_Data + (i * 4)));
    }
    return TRUE;


}

BOOLEAN Mc_To_W(PSHA1_Data Data) {
    int B_i = Data->Mc_Len_Bit / 512;
    ULONG32(*nW)[80] = (ULONG32(*)[80])malloc(B_i * 80 * 4);//每个512bit块64个W
    for (int i = 0; i < B_i; i++) {
        for (int j = 0; j < 16; j++) {//初始化 Bi(W0 - w15)
            nW[i][j] = (ULONG32)(Data->Mc[i * 512 / 8 + j * 4] << 24 | Data->Mc[i * 512 / 8 + j * 4 + 1] << 16 | Data->Mc[i * 512 / 8 + j * 4 + 2] << 8 | Data->Mc[i * 512 / 8 + j * 4 + 3]);
        }

        for (int j = 16; j < 80; j++) {//初始化 Bi(W16 - W63)
            nW[i][j] = SL(nW[i][j - 3] ^ nW[i][j - 8] ^ nW[i][j - 14] ^ nW[i][j - 16], 1);
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
    SHA1_Data test(hx);
    Mc_To_W(&test);
    SHA1_HASH(&test);
    printf("消息：%s\nSHA1 Hash结果:\n", hx);
    dumpbuf(test.Hash_Data, 20);
    printf("\n");
    system("pause");
}