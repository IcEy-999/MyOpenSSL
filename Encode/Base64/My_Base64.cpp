#include <iostream>
#include <Windows.h>
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

class Base64_Data{
    PUCHAR M;
    ULONG32 M_Len;
    PUCHAR Mc;
    ULONG32 Mc_Len;
    VOID Get_UCHAR(PUCHAR Tag);
    VOID Get_Tag(PUCHAR C);
public:
    Base64_Data(PUCHAR S,ULONG32 Len);
    ~Base64_Data();
    VOID En();//编码
    VOID De();//解码
    PUCHAR Out;
    ULONG32 Out_Len;
};

Base64_Data::~Base64_Data(){
    if(M != NULL)
    {
        free(M);
        free(Out);
    }
}

Base64_Data::Base64_Data(PUCHAR S,ULONG32 Len){
    if(Len ==0)
        return;
    M_Len = Len;
    M = (PUCHAR)malloc(Len);
    memcpy(M,S,Len);
}

VOID Base64_Data::Get_UCHAR(PUCHAR Tag){
    UCHAR ls = *Tag;
    if(ls<=25){
        ls+=0x41;
    }else if(ls<=51){
        ls+=0x47;
    }else if(ls<=61){
        ls-=4;
    }else if(ls==62){
        ls = 43;
    }else{
        ls = 47;
    }
    *Tag = ls;
}

VOID Base64_Data::Get_Tag(PUCHAR C){
    UCHAR ls = *C;
    if(ls ==0){
    }else if(ls==43){
        ls = 62;
    }else if(ls ==47){
        ls = 63;
    }else if(ls <=57){
        ls+=4;
    }else if(ls<=90){
        ls-=0x41;
    }else if(ls<=122){
        ls-=0x47;
    }
    *C = ls;
}

VOID Base64_Data::De(){
    PUCHAR Buffer = (PUCHAR)malloc(M_Len*6);
    memset(Buffer,0,M_Len*6);
    Out_Len = M_Len*6/8;//肯定能整除
    Out = (PUCHAR)malloc(Out_Len+1);
    memset(Out,0,Out_Len+1);
    for(int i =0;i<M_Len;i++){
        if(M[i]=='='){
            M[i] = 0;
        }
        Get_Tag(&M[i]);
    }
    for(int i=0;i<M_Len*6;i++){
        Buffer[i] = Get_Bit(&M[i/6],5-i%6);
    }
    for(int i =0;i<Out_Len;i++){
        for(int j=7;j>=0;j--){
            Set_Bit(&Out[i],j,Buffer[8*i+(7-j)]);
        }
    }


}

VOID Base64_Data::En(){
    Mc_Len = M_Len;
    ULONG32 a = M_Len/3;
    ULONG32 b = M_Len%3;
    if(b>0){
        Out_Len = a*4 +4;
        for(;Mc_Len%3!=0;Mc_Len++);
    }else{
        Out_Len = a*4;
    }
    Out = (PUCHAR)malloc(Out_Len+1);
    memset(Out,0,Out_Len+1);
    Mc = (PUCHAR)malloc(Mc_Len);
    memset(Mc,0,Mc_Len);
    memcpy(Mc,M,M_Len);

    PUCHAR Buffer = (PUCHAR)malloc(Mc_Len*8);
    memset(Buffer,0,Mc_Len*8);
    for(int i=0;i<Mc_Len*8;i++){
        Buffer[i] = Get_Bit(&Mc[i/8],7-i%8);
    }
    for(int i =0;i<Out_Len;i++){
        for(int j=5;j>=0;j--){
            Set_Bit(&Out[i],j,Buffer[6*i+(5-j)]);
        }
        Get_UCHAR(&Out[i]);
    }
    ULONG32 bm = M_Len*8/6;//在最后补 等于号
    ULONG32 bmy = M_Len*8%6;
    if(bmy >0){
        bm+= 1;
        for(int i=bm;i<Out_Len;i++){
            Out[i] = '=';
        }
    }

}

int main(){
    //编码
    UCHAR En[] = "I'm Zy!Hello!KK,你好吗？";
    Base64_Data Entest(En,28);
    Entest.En();
    printf("Base64 Encode:\n%s\n",Entest.Out);

    //解码
    Base64_Data Detest(Entest.Out,Entest.Out_Len);
    Detest.De();
    printf("Base64 Decode:\n%s\n",Detest.Out);
}

