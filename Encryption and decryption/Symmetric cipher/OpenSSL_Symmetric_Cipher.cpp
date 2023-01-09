#include<iostream>
#include<Windows.h>
#include<openssl/evp.h>
 
//加密（加密方式，密钥，初始向量，明文地址，明文长度，输出地址）
BOOLEAN EnCryption(const EVP_CIPHER* type, char* Key, char* Iv, char* Plaintext, int Plaintext_Len, char* Output, int* Output_Len) {
	int outbuffer_len;//临时密文长度
	int outbuffer_tmplen;//临时结尾密文长度
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();//初始化
	EVP_CIPHER_CTX_init(ctx);//初始化2
	EVP_EncryptInit_ex(ctx, type, NULL, (const unsigned char*)Key, (const unsigned char*)Iv);//加密初始化3


	//加密
	if (!EVP_EncryptUpdate(ctx, (unsigned char*)Output, &outbuffer_len, (unsigned char*)Plaintext, (int)Plaintext_Len)) {
		printf("EVP_EncryptUpdate\n");
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	//补字节后加密剩下的
	if (!EVP_EncryptFinal_ex(ctx, (unsigned char*)(Output + outbuffer_len), &outbuffer_tmplen)) {
		printf("EVP_EncryptFinal_ex\n");
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}
	*Output_Len = outbuffer_len + outbuffer_tmplen;
	EVP_CIPHER_CTX_free(ctx);
	return true;

}

//解密（加密方式，密钥，初始向量，密文地址，密文长度，输出地址）
BOOLEAN DeCryption(const EVP_CIPHER* type, char* Key, char* Iv, char* Ciphertext, int Ciphertext_Len, char* Output, int* Output_Len) {
	int outbuffer_len;//临时密文长度
	int outbuffer_tmplen;//临时结尾密文长度
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();//初始化
	EVP_CIPHER_CTX_init(ctx);//初始化2
	EVP_DecryptInit_ex(ctx, type, NULL, (const unsigned char*)Key, (const unsigned char*)Iv);//加密初始化3
	if (!EVP_DecryptUpdate(ctx, (unsigned char*)Output, &outbuffer_len, (unsigned char*)Ciphertext, Ciphertext_Len)) {
		printf("EVP_DecryptUpdate\n");
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	if (!EVP_DecryptFinal_ex(ctx, (unsigned char*)(Output + outbuffer_len), &outbuffer_tmplen)) {
		printf("EVP_DecryptFinal_ex\n");
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}
	
	*Output_Len = outbuffer_len + outbuffer_tmplen;
	EVP_CIPHER_CTX_free(ctx);
	return true;
}

int main() {
	char key[] = "kk,i love you!";
	char iv[] = "i am zzy";
	char ptext[] = "加密这段文本吖！！";
	char Enout[1024] = { 0 };
	char Deout[1024] = { 0 };
	int Enout_Len = 0;//实际加密字节数
	int Deout_Len = 0;//实际解密字节数
	//加密
	printf("加密前:\n");
	printf("%s\n", ptext);
	if (!EnCryption(EVP_des_cbc(), key, iv, ptext, strlen(ptext), Enout, &Enout_Len))
	{
		printf("加密失败");
	}
	printf("\n密文:\n");
	printf("%s\n", Enout);
	//解密
	if (!DeCryption(EVP_des_cbc(), key, iv, Enout, Enout_Len, Deout, &Deout_Len))
	{
		printf("解密失败");
	}
	printf("\n明文:\n");
	printf("%s\n", Deout);
	system("pause");

}