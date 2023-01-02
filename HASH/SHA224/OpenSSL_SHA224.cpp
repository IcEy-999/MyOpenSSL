#include<iostream>
#include "openssl/evp.h"


int hash(const unsigned char *message, size_t len, unsigned char *hash, unsigned int *hash_len)
{
	EVP_MD_CTX *md_ctx;
	const EVP_MD *md;

	md = EVP_sha224();//修改HASH方式
	md_ctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(md_ctx, md, NULL);
	EVP_DigestUpdate(md_ctx, message, len);
	EVP_DigestFinal_ex(md_ctx, hash, hash_len);
	EVP_MD_CTX_free(md_ctx);
	return 0;
}

int main(){
    const unsigned char jm[] = "aaaaaaaaaa";
    int size = 10;
    unsigned int out_len = 0;
    unsigned char buff[28]={0};
    hash(jm,size,buff,&out_len);
}