#include<iostream>
#include<Windows.h>
#define B 1600  //对于SHA3 固定
#define Nr 24  //对于SHA3 固定
#define W 64  //对于SHA3 固定
#define L 6  //对于SHA3 固定
#define R 1088 //SHA3_224 : 1152   SHA3_256 : 1088  SHA3_384 : 832  SHA3_512 : 576

#define A(x,y,z) (W*(5*y+x)+z)

VOID Set_Bit(PUCHAR Data, ULONG32 OffSet, UCHAR b) {
    ULONG32 Byte = OffSet / 8;
    ULONG32 Bit = OffSet % 8;
    UCHAR O = 1 << Bit;
    if (b == 0x1) {
        Data[Byte] |= O;
    }
    else {
        O = ~O;
        Data[Byte] &= O;
    }

}

UCHAR Get_Bit(PUCHAR Data, ULONG32 OffSet) {
    ULONG32 Byte = OffSet / 8;
    ULONG32 Bit = OffSet % 8;
    UCHAR O = 1 << Bit;
    UCHAR k = Data[Byte] & O;
    if (k == 0) {
        return 0;
    }
    else {
        return 1;
    }
}

//x mod y
int mod(int x, int y) {
    if (x >= 0) {
        return x % y;
    }
    else {
        int z = -x;
        return (y - (z % y))%y;
    }
}

int pow(int x, int y) {
    int xx = 1;
    for (int i = 0; i < y; i++) {
        xx *= x;
    }
    return xx;
}

class SHA3_256_Data {
    PUCHAR M;
    ULONG32 M_Len_Bit;
    PUCHAR Mc;
    ULONG32 Mc_Len_Bit;
    UCHAR rc(int t);
    VOID theat(PUCHAR S);
    VOID rho(PUCHAR S);
    VOID pi(PUCHAR S);
    VOID chi(PUCHAR S);
    VOID iota(PUCHAR S, int Ir);
    VOID Rnd(PUCHAR S, int Ir);
    VOID KECCAK_P(PUCHAR S);
    
public:
    PUCHAR Hash_Data;
    SHA3_256_Data(PUCHAR M, ULONG32 Byte_Len);
    ~SHA3_256_Data();
    VOID HASH();
};

SHA3_256_Data::~SHA3_256_Data() {
    free(Mc);
    free(M);
    free(Hash_Data);
}

SHA3_256_Data::SHA3_256_Data(PUCHAR M, ULONG32 Byte_Len) {
    this->M_Len_Bit = Byte_Len * 8;
    ULONG32 Len_bf = this->M_Len_Bit;
    ULONG64 bl = 0;
    int mod = this->M_Len_Bit % R;
    if (mod + 8 <= R && mod > 0) {
        while ((Len_bf + 8) % R != 0) {
            Len_bf += 8;
        }
    }
    else {
        while ((Len_bf) % R != 0) {//补长度，R
            Len_bf += 8;
        }
        Len_bf += 8;
        while ((Len_bf + 8) % R != 0) {//留一个8bit and 64bit整数
            Len_bf += 8;
        }
    }
    ULONG32 pout = Len_bf + 8;
    PUCHAR buffer = (PUCHAR)malloc((pout) / 8);
    PUCHAR M_buffer = (PUCHAR)malloc((this->M_Len_Bit) / 8);
    memset(buffer, 0, (pout) / 8);
    memcpy(buffer, M, this->M_Len_Bit / 8);
    buffer[this->M_Len_Bit / 8] |= 0x6;
    buffer[Len_bf / 8] |= 0x80;
    this->M = M_buffer;
    this->Mc = buffer;
    this->Mc_Len_Bit = pout;
    this->Hash_Data = (PUCHAR)malloc((B - R)/2 / 8);
}

UCHAR SHA3_256_Data::rc(int t) {
    UCHAR r[9] = { 1,0,0,0,0,0,0,0,0 };
    if (mod(t, 255) == 0) {
        return 1;
    }
    for (int i = 1; i <= mod(t, 255); i++) {
        memcpy(&r[1], &r[0], 8);
        r[0] = 0;
        r[0] = r[0] ^ r[8];
        r[4] = r[4] ^ r[8];
        r[5] = r[5] ^ r[8];
        r[6] = r[6] ^ r[8];
        //memcpy(&r[0], &r[1], 8);
    }
    return r[0];
}

VOID SHA3_256_Data::theat(PUCHAR S) {
    PUCHAR Sc = (PUCHAR)malloc(B / 8);
    memset(Sc, 0, B / 8);
    PUCHAR C = (PUCHAR)malloc(5 * W / 8);
    PUCHAR D = (PUCHAR)malloc(5 * W / 8);
    memset(C, 0, 5 * W / 8);
    memset(D, 0, 5 * W / 8);
    for (int x = 0; x < 5; x++) {
        for (int z = 0; z < W; z++) {
            Set_Bit(C, W * x + z, Get_Bit(S, A(x, 0, z)) ^ Get_Bit(S, A(x, 1, z)) ^ Get_Bit(S, A(x, 2, z)) ^ Get_Bit(S, A(x, 3, z)) ^ Get_Bit(S, A(x, 4, z)));
        }
    }
    for (int x = 0; x < 5; x++) {
        for (int z = 0; z < W; z++) {
            Set_Bit(D, W * x + z, Get_Bit(C, W * mod(x - 1, 5) + z) ^ Get_Bit(C, W * mod(x + 1, 5) + mod(z - 1, W)));
        }
    }

    for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
            for (int z = 0; z < W; z++) {
                Set_Bit(Sc, A(x, y, z), Get_Bit(D, W * x + z) ^ Get_Bit(S, A(x, y, z)));
            }
        }
    }
    memcpy(S, Sc, B / 8);
    free(Sc);
    free(C);
    free(D);
}

VOID SHA3_256_Data::rho(PUCHAR S) {
    PUCHAR Sc = (PUCHAR)malloc(B / 8);
    memset(Sc, 0, B / 8);
    //memcpy(Sc, S, B / 8);
    for (int z = 0; z < W; z++) {
        Set_Bit(Sc, A(0, 0, z), Get_Bit(S, A(0, 0, z)));
    }
    int x = 1, y = 0;
    int newx, newy;
    for (int t = 0; t < 24; t++) {
        for (int z = 0; z < W; z++) {
            Set_Bit(Sc, A(x, y, z), Get_Bit(S, A(x, y, mod(z - ((t + 1) * (t + 2) / 2), W))));
        }
        newx = y%5;
        newy =(2 * x + 3 * y)% 5;
        x = newx;
        y = newy;
    }
    memcpy(S, Sc, B / 8);
    free(Sc);
}

VOID SHA3_256_Data::pi(PUCHAR S) {
    PUCHAR Sc = (PUCHAR)malloc(B / 8);
    int j = 0;
    memset(Sc, 0, B / 8);
    for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
            for (int z = 0; z < W; z++) {
                j = mod(x + (3 * y), 5);
                Set_Bit(Sc, A(x, y, z), Get_Bit(S, A(j,x,z)));
            }
        }
    }
    memcpy(S, Sc, B / 8);
    free(Sc);
}

VOID SHA3_256_Data::chi(PUCHAR S) {
    PUCHAR Sc = (PUCHAR)malloc(B / 8);
    memset(Sc, 0, B / 8);
    for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
            for (int z = 0; z < W; z++) {
                Set_Bit(Sc, A(x, y, z), Get_Bit(S, A(x, y, z)) ^ ((Get_Bit(S, A(mod(x + 1, 5), y, z)) ^ 1) && Get_Bit(S, A(mod(x + 2, 5), y, z))));
            }
        }
    }
    memcpy(S, Sc, B / 8);
    free(Sc);
}

VOID SHA3_256_Data::iota(PUCHAR S, int Ir) {
    PUCHAR Sc = (PUCHAR)malloc(B / 8);
    memcpy(Sc, S, B / 8);
    UCHAR RC[W] = { 0 };
    for (int j = 0; j <= L; j++) {
        int ls = pow(2, j) - 1;
        RC[ls] = rc(j + 7 * Ir);
    }

    for (int z = 0; z < W; z++) {
        Set_Bit(Sc, A(0, 0, z), Get_Bit(Sc, A(0, 0, z)) ^ RC[z]);
    }
    memcpy(S, Sc, B / 8);
    free(Sc);
}

VOID SHA3_256_Data::Rnd(PUCHAR S, int Ir) {
    theat(S);
    rho(S);
    pi(S);
    chi(S);
    iota(S, Ir);
}

VOID SHA3_256_Data::KECCAK_P(PUCHAR S) {
    for (int ir = 12 + 2 * L - Nr; ir <= 12 + 2 * L - 1; ir++) {
        Rnd(S, ir);
    }
}

VOID SHA3_256_Data::HASH() {
    ULONG32 B_i = Mc_Len_Bit / R;
    PUCHAR S = (PUCHAR)malloc(B / 8);
    memset(S, 0, B / 8);
    for (ULONG32 i = 0; i < B_i; i++) {
        for (int j = 0; j < R / 8; j++) {
            S[j] ^= Mc[i * R / 8 + j];
        }
        KECCAK_P(S);
    }
    memcpy(Hash_Data, S, ((B - R) / 2 / 8));
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
    SHA3_256_Data test(hx,10);
    test.HASH();
    printf("消息：%s\nSHA3_224 Hash结果:\n", hx);
    dumpbuf(test.Hash_Data, (B - R)/2/8);
    printf("\n");
    system("pause");
}