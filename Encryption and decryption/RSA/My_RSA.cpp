#include"bignum.h"
#pragma comment(lib,"bignum_lib.lib")

class RSA_Data{
    bignum d,n;//Key
    public:
    bignum* M;
    ULONG64 M_Len;
    bignum* Out;
    ULONG64 Out_Len;
    RSA_Data(PUCHAR M,ULONG32 Len);
    BOOLEAN Set_Key(const char* ds,const char* ns);
    BOOLEAN En_De();
    VOID Print_Out();
};

RSA_Data::RSA_Data(PUCHAR Ms,ULONG32 Len){
    M = new bignum[Len];
    Out = new bignum[Len];
    for(ULONG32 i=0;i<Len;i++){
        M[i].U64[0] = (ULONG64)Ms[i];
    }
    M_Len = Len;
    Out_Len = Len;
}

BOOLEAN RSA_Data::Set_Key(const char* ds,const char* ns){
    if(!d.set(ds) || !n.set(ns)){
            printf("RSA Key Set error!!\n");
            d.clear();n.clear();
            return FALSE;
        }
}

BOOLEAN RSA_Data::En_De(){
    bignum ls,js,one;
    if(bignum_cmp(d,ls)==2){
        return FALSE;
    }
    one.U64[0]=1;
    for(ULONG32 i=0;i<M_Len;i++){
        ls.clear();js.clear();
        ls.U64[0]=1;
        continue0:
        while(bignum_cmp(ls,n)==0){
            ls = bignum_imul(ls,M[i]);
            js = bignum_add(js,one);
        }
        ls = bignum_mod(ls,n);
        if(bignum_cmp(js,d) == 0){
            goto continue0;
        }
        Out[i] = ls;
    }
    return TRUE;
}

VOID RSA_Data::Print_Out(){
    for(ULONG32 i=0;i<Out_Len;i++){
        Out[i].out();
        printf(" ");
    }
}

int main(){
    UCHAR hx[] = "helloworld123";
    RSA_Data d(hx,13);
    d.Set_Key("0x5","0x81");//PK or SK
    d.En_De();
    d.Print_Out();
}