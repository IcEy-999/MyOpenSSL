#include"bignum.h"
#pragma comment(lib,"bignum_lib.lib")
VOID C_T_R(PUCHAR s, ULONG32 length) {
    UCHAR ls = 0;
    for (int i = 0; i < length/2; i++) {
        ls = s[i];
        s[i] = s[length - i - 1];
        s[length - i - 1] = ls;
    }
}

bignum two;
bignum one;
bignum zero;
bignum ten;


class RSA_Data {
    bignum n,e,d,p,q,dmp,dmq,crt;//Key
    bignum En_De_Tool(bignum* pMc, bignum* pnum,  bignum* pn);
    VOID bignum_2_uchar(bignum *bn,IN OUT PUCHAR buffer,IN OUT PULONG32 offset);
public:
    PUCHAR M;
    ULONG64 M_Len;
    bignum* Mc;//Mc is EB
    ULONG32 Mc_Len;
    bignum* Cc;
    ULONG32 Cc_Len;
    bignum* Out;
    ULONG64 Out_Len;
    RSA_Data();
    ~RSA_Data();
    BOOLEAN De_Only_d_n();
    VOID Set_Public_Key(bignum n, bignum e);
    VOID Set_Private_Key(bignum n, bignum e, bignum d, bignum p, bignum q, bignum dmp, bignum dmq, bignum crt);
    BOOLEAN Set_En_Information(PUCHAR Ms, ULONG32 Len, ULONG32 Wide, UCHAR BT);
    VOID Set_De_Information(bignum* PCc, ULONG32 Len);
    BOOLEAN En();
    BOOLEAN De();
    VOID Print_Out();
};

RSA_Data::RSA_Data() {
    M = NULL; M_Len = 0; Mc = NULL; Mc_Len = 0; Cc = NULL; Cc_Len = 0; Out = NULL; Out_Len = 0;
}

RSA_Data::~RSA_Data() {
    if (M != NULL)
        delete M;
    if (Mc != NULL)
        delete[]Mc;
    if (Cc != NULL)
        delete[]Cc;
    if (Out != NULL)
        delete[]Out;
}

bignum RSA_Data::En_De_Tool(bignum* pMc, bignum* pnum, bignum* pn) {
    bignum t = *pMc;
    bignum ls = one;
    bignum num = *pnum;
    while (bignum_cmp(num, zero) != 2) {
        if ((num.U64[0] & 1) != 0) {
            ls = bignum_imul(ls, t);
            ls = bignum_mod(ls, *pn);
        }
        num = bignum_rs(num, 1);
        t = bignum_imul(t, t);
        t = bignum_mod(t, *pn);
    }
    return ls;
}

VOID RSA_Data::Set_Public_Key(bignum n, bignum e) {
    this->n = n; this->e = e;
}

VOID RSA_Data::Set_Private_Key(bignum n, bignum e, bignum d, bignum p, bignum q, bignum dmp, bignum dmq, bignum crt) {
    this->n = n; this->e = e; this->d = d; this->p = p; this->q = q; this->dmp = dmp; this->dmq = dmq; this->crt = crt;
}

//明文，明文字节数，加密解密宽度，BT = 0、1 私钥操作 BT = 2 公钥操作
BOOLEAN RSA_Data::Set_En_Information(PUCHAR Ms, ULONG32 Len,ULONG32 Wide,UCHAR BT) {
    ULONG32 EB_Num = Len / (Wide/8 - 11),ls = 0, Last_D_Len = Len % (Wide/8 - 11);
    ULONG32 Last_PS_Len = Wide/8 - Last_D_Len - 3;;//最后一段PS要补多少个字节
    UCHAR xj = 0;
    srand(time(NULL));
    if (Wide % 1024 != 0)
        return FALSE;
    if (Last_D_Len != 0)
        EB_Num++;
    M = (PUCHAR)malloc(EB_Num * Wide/8);
    memset(M, 0, EB_Num * Wide/8);
    M_Len = EB_Num * Wide / 8;
    Mc = (bignum*)malloc(sizeof(bignum) * EB_Num);
    memset(Mc, 0, sizeof(bignum) * EB_Num);
    Mc_Len = EB_Num;
    Out = (bignum*)malloc(sizeof(bignum) * EB_Num);
    memset(Out, 0, sizeof(bignum) * EB_Num);
    Out_Len = EB_Num;
    M_Len = EB_Num * Wide/8;
    for (int i = 0; i < EB_Num; i++) {
        //zero
        M[i * Wide/8] = 0;
        //BT
        M[i * Wide/8 + 1] = BT;
        ls = 8;
        if (i + 1 == EB_Num)
            ls = Last_PS_Len;
            
        //PS
        int j = 0;
        switch (BT)
        {
        case 0: {
            for (j = 0; j < ls; j++) {
                M[i * Wide/8 + 2 + j] = 0;
            }
            break;
        }
        case 1: {
            for (j = 0; j < ls; j++) {
                M[i * Wide/8 + 2 + j] = 0xff;
            }
            break;
        }
        case 2: {
            for (j = 0; j < ls; j++) {
                do {
                    xj = (UCHAR)rand();
                } while (xj == 0);
                M[i * Wide/8 + 2 + j] = xj;
            }
            break;
        }
        default:
            return FALSE;
        }
        //zero
        M[i * Wide/8 + 2 + j] = 0;

        //D
        ls = Wide/8 - 11;
        if (i + 1 == EB_Num)
            ls = Last_D_Len;
        memcpy(&M[i * Wide/8 + 2 + j + 1], &Ms[i*(Wide/8 - 11)], ls);
        C_T_R(&M[i*Wide/8], Wide / 8);
        //Mc[i].set((const char*)&M[i * Wide / 8]);
        memcpy(&Mc[i], &M[i * Wide / 8], Wide / 8);
        Mc[i].set_len();
    }
    return true;
}

VOID RSA_Data::Set_De_Information(bignum* PCc,ULONG32 Len) {
    Out_Len = Cc_Len = Len;
    Cc = new bignum[Len]();
    memcpy(Cc, PCc, Len * sizeof(bignum));
    Out = new bignum[Len]();
}

BOOLEAN RSA_Data::En() {
    for (int i = 0; i < Mc_Len; i++) {
        Out[i] = En_De_Tool(&Mc[i], &e, &n);
    }
    return true;
}

BOOLEAN RSA_Data::De() {
    //使用了 中国剩余定理（CRT） 加速运算
    bignum* mp = new bignum, * mq = new bignum, *h = new bignum;
    for (int i = 0; i < Cc_Len; i++) {
        *mp = En_De_Tool(&Cc[i], &dmp, &p);
        *mq = En_De_Tool(&Cc[i], &dmq, &q);
        if (bignum_cmp(*mp, *mq) == 1) {
            *h = bignum_sub(*mp, *mq);
        }
        else {
            *h = bignum_sub(*mq, *mp);
            *h = bignum_sub(p, *h);
        }
        *h = bignum_imul(*h, crt);
        if (bignum_cmp(*h, p) == 1) {
            *h = bignum_mod(*h, p);
        }
        *h = bignum_imul(*h, q);
        Out[i] = bignum_add(*h, *mq);
    }
    delete mp, mq, h;
    return TRUE;
}

BOOLEAN RSA_Data::De_Only_d_n() {
    for (int i = 0; i < Cc_Len; i++) {
        Out[i] = En_De_Tool(&Cc[i], &d,  &n);
    }
    return TRUE;
}

VOID RSA_Data::Print_Out() {
    PUCHAR buffer = new UCHAR[0x100]();
    ULONG32 len = 0;
    for (ULONG32 i = 0; i < Out_Len; i++) {
        Out[i].out();
        printf(" \n\n");
        if(Cc!=NULL)
            bignum_2_uchar(&Out[i],buffer,&len);
    }
    if(Cc!=NULL)
        printf("all:%s\n\n",buffer);
    delete[] buffer;
}

VOID RSA_Data::bignum_2_uchar(bignum *bn,IN OUT PUCHAR buffer,IN OUT PULONG32 offset){
    PUCHAR pend = (PUCHAR)&bn->U64[bn->U64_Len],pstart = (PUCHAR)&bn->U64[0];
    ULONG32 of = 0;
    pend = pend - 10;//跳过  00 + BT + (8个随机字节)
    while(*pend!=0x00){
        pend--;
    }
    of = (ULONG64)pend - (ULONG64)pstart;
    for(int i=0;i<of;i++){
        buffer[*offset + i] = *(pend - i-1);
    }
    *offset += of;

}

int main() {
    one.U64[0] = 1;
    two.U64[0] = 2;
    ten.U64[0] = 10;
    ULONG64 En_time, De_time;
    UCHAR hx[] = "abc";
    RSA_Data *RSAEn_test = new RSA_Data,*RSADe_test1 = new RSA_Data,*RSADe_test2 = new RSA_Data;
    bignum *n = new bignum,*e = new bignum,*d = new bignum,*p = new bignum,*q = new bignum,*dmp = new bignum,*dmq = new bignum,*crt = new bignum;
    //bignum* c = new bignum;
    n->set("0xAC5A73C08928872F5142E03EA6879247DA51BB4A05B9943B4D53F13403B2AB26925B10A0E728C041B7DC85E7B4051DDA70674A15A19EABD0AD93BC859480AE7C28CC1113BDE4ED13E2CC3C3F5BF0D39B7AC7E0E7D7632669C7248F3B34DBD98A617FB211FF59790436CAFD8F23E7F68F2E0308891DDD66481F8D3A30ADD93878ACB36E4F0690B75BA45FD5C2B19416D2FD881AACD7B204C6D3C4502E8D1477A756214C6C0B0379CD81F6AE60F4DCD2DBF438D13D26EF2F55F69749FA59AC4CB5E2C88BF3684301DEEAD0BC704D1C56D4FBA4D5367628B449577DAC975BD74ED6870D1802D8B55156F8C5D09523B4197105B73ED204ADE6E6068B78D645AC3DED");
    e->set("0x10001");
    d->set("0x2A5B485B26DA08EEFDFF7B70AA286330B95CA0B47E57AF302BBED7663B0A6BB95CFA7849B2C5770A2F8F48713AF28EF5A1EE206CD47D542842A02E127DFE69E3257B912ED2DA31D1534971FCF831652FAEAAF480C5941E5A9C90458AFD609243C9D64202DE4834CF6E4FD0A49EE460D9AB2B1FABE2E5083FED511DDDDCBBA77EC955E25FD8D8092949C9F2B7CCC61F37A05F8B39E7EC1A83A3258A4E15FF91117496DE359C1028349DA9E850F47D783D6EA8B44EBA7C656887AE3EA34516DA8DBC7664810D9692FF3BD6983CA4A9C526053FC6F99359EA392A0F93EEAC29F802F8E19E3A326CD7743E578A7339EB187058402DC80C81C0C5D7FDE94BA72EF519");
    p->set("0x00D901735D7AF0EC42B4C41B2AF512137ABD51B0D57B61FFF3D13AB2064ED87454FC2BA71473C110EB4F96203F1BB63FE486587266588C2C6F89685C65E08C2E9EDB277DF193AB488BA489EEFF12DC4CC59D34438BADA4B6D35E427B0B8E5098895DCB46397F1C4AB7626F73B638FBA1C5BD90D3A8EF32B710D20126B91A546B3F");
    q->set("0x00CB52EF3FD2C54E0452435083F8AFB9F26F9789524DC0BCB2BFC2D8F1156C200B057D6FFDF0C011A4255DF2E41191F272912916D859ECA119E873452ADF84631046386BA2BF344F26D9F90B61518B92EAAD78ABF79CF0BF94DE4B372B39A1BAF5A179A7E41B35E06D54DAC8E925AF4E72769607D8C78145235CFAF63FE02EE7D3");
    dmp->set("0x6224CDD05171F4E89668BB00CAA5CA3990B6098C03A966E11697BD3C2D1CA840676C36BC813DA83144655960316053B53F2D714FE86C3D0C94D0A6394D3D1938AF554518A4F8AA6EBD93C48B88342A64959CB58FCE90D83EF03A90FBC0F9A2833DF0596A579AAC10146CE3A05E552FED06B721831DEB89F0098A8BC0DBAFA271");
    dmq->set("0x14F9BC56E03E9C9AD385C043AD1F2BD6B7EE712B3D7C39BB530F1DE4592A6B6FD7A4262E936CAD253AF9A33A2619E162325983D2D40C165E9EDD6D704BD8D383754B12C79A64221A46F86B5521DD7D4D9A91CD63E11BF117C18B0EE8F5AC1AA6867F0F73F7DEAA057D7088B38CC0B61E16DFC97572B78253709F2F524DA56923");
    crt->set("0x7ECD05E781CFC0CE985CE621FDFAF4C49FE82BB374DD401B9F0E9CF79A01F832045FF36FE84CC9D8D7D65706F7EEEE7E93BC0797D9F93C0B47FDC127CF8F9E2DF4CA1CAC425431499658F93C0FFC30B48DCACF4B65BEC4ED995AB80A888E630FCE883EB710BA94D17F75B6A2117FCAD957C4678F993B7E4141300216C6FF6ED1");
    //加密测试！！！
    En_time = GetTickCount64();
    RSAEn_test->Set_En_Information(hx, 3, 2048, 2);
    RSAEn_test->Set_Public_Key(*n, *e);
    RSAEn_test->En();
    En_time = GetTickCount64() - En_time;//6f06 ms ,  28s  ,1.3s
    printf("\n## RSA - PKCS ##\n\nplaintext:%s \nEn_time:%lld ms EnCode:\n",hx,En_time);
    RSAEn_test->Print_Out();
    
    //解密测试 1 ！！！ CRT加速
    De_time = GetTickCount64();
    RSADe_test1->Set_De_Information(RSAEn_test->Out, RSAEn_test->Out_Len);
    RSADe_test1->Set_Private_Key(*n, *e, *d, *p, *q, *dmp, *dmq, *crt);
    RSADe_test1->De();
    De_time = GetTickCount64() - De_time;
    printf("\n\nDe_time:%lld ms DeCode:\n", De_time);
    RSADe_test1->Print_Out();

    //解密测试 2 ！！！仅使用 d and n
    De_time = GetTickCount64();
    RSADe_test2->Set_De_Information(RSAEn_test->Out, RSAEn_test->Out_Len);
    RSADe_test2->Set_Private_Key(*n, *e, *d, *p, *q, *dmp, *dmq, *crt);

    RSADe_test2->De_Only_d_n();
    De_time = GetTickCount64() - De_time;
    printf("\nDe_time:%lld ms DeCode:\n", De_time);
    RSADe_test2->Print_Out();
    system("pause");
}


