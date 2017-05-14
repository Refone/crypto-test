#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/crypto.h>
#include <asm/crypto/aes.h>
//#include "crypto.h"

//#define rdtscll(val) do { 
//         unsigned int _eax, _edx; 
//         asm volatile("rdtsc" : "=a" (_eax), "=d" (_edx)); 
//         (val) = ((unsigned long)_eax) | (((unsigned long)_edx)<<32); 
//} while(0)

static const unsigned char KEY[] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
									  0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};

static const unsigned char IV[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
									0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};

static struct crypto_aes_ctx _ctx;
static struct crypto_aes_ctx *ctx = &_ctx;

extern void AESENC_encrypt (const unsigned char *in,
							unsigned char *out,
							const unsigned char ivec[16],
							unsigned long length,
							unsigned char *KS,
							int nr);

extern void AESENC_decrypt (const unsigned char *in,
							unsigned char *out,
							const unsigned char ivec[16],
							unsigned long length,
							unsigned char *KS,
							int nr);

void aesenc_encrypt(void* src, void* dst, unsigned long length)
{
	AESENC_encrypt((unsigned char*)src, (unsigned char*)dst, 
					IV, length, (unsigned char *)ctx->key_enc, 10);
}

void aesenc_decrypt(void* src, void* dst, unsigned long length)
{
	AESENC_decrypt((unsigned char*)src, (unsigned char*)dst,
					IV, length, (unsigned char *)ctx->key_dec, 10);
}

void aes_encrypt(void* src, void* dst, unsigned long length)
{
	int i;
	for (i=0; i<length/16; i++) {
		crypto_aes_encrypt_x86(ctx, (u8 *)(dst+16*i), (u8 *)(src+16*i));
	}
}

void aes_decrypt(void* src, void* dst, unsigned long length)
{
	int i;
	for (i=0; i<length/16; i++) {
		crypto_aes_decrypt_x86(ctx, (u8 *)(dst+16*i), (u8 *)(src+16*i));
	}
}

void print_text(uint8_t* src, unsigned long length)
{
	int i;
	for (i=0; i<length/8; i++) {
        printk("%02x %02x %02x %02x %02x %02x %02x %02x\n",
        src[8*i+0],src[8*i+1],src[8*i+2],src[8*i+3],
        src[8*i+4],src[8*i+5],src[8*i+6],src[8*i+7]);
	}
}

static int init_crypto(void)
{
	unsigned long s_time, e_time;
	unsigned long vpage1, vpage2;
	vpage1 = __get_free_pages(GFP_KERNEL, 9);
	vpage2 = __get_free_pages(GFP_KERNEL, 9);
//	ALIGN16 uint8_t TEST_PLAIN[] = 
//	   {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
//		0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
//		0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,
//		0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
//		0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,
//		0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
//		0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,
//		0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10};

//	ALIGN16 uint8_t CBC128_EXPECTED[] = 
//	   {0x76,0x49,0xab,0xac,0x81,0x19,0xb2,0x46,
//		0xce,0xe9,0x8e,0x9b,0x12,0xe9,0x19,0x7d,
//		0x50,0x86,0xcb,0x9b,0x50,0x72,0x19,0xee,
//		0x95,0xdb,0x11,0x3a,0x91,0x76,0x78,0xb2,
//		0x73,0xbe,0xd6,0xb8,0xe3,0xc1,0x74,0x3b,
//		0x71,0x16,0xe6,0x9e,0x22,0x22,0x95,0x16,
//		0x3f,0xf1,0xca,0xa1,0x68,0x1f,0xac,0x09,
//		0x12,0x0e,0xca,0x30,0x75,0x86,0xe1,0xa7};

//	ALIGN16 uint8_t VECTOR[64];

	printk("crypto module init.\n");
	
	crypto_aes_expand_key(ctx, KEY, AES_KEYSIZE_128);

/************* crypto_aes  *****************/
//	printk("TEST_PLAIN:\n");
//	print_text(TEST_PLAIN, 64);
//	aes_encrypt(TEST_PLAIN, VECTOR, 64);		
//	printk("TEST_CIPHER:\n");
//	print_text(VECTOR, 64);
//	aes_decrypt(VECTOR, VECTOR, 64);
//	printk("TEST_DECRYPT:\n");
//	print_text(VECTOR, 64);
/************ crypto_aes end ***************/

/************* AESENC TEST *****************/
//	printk("TEST_PLAIN:\n");
//	print_text(TEST_PLAIN, 64);
//	aesenc_encrypt(TEST_PLAIN, VECTOR, 64);
//	printk("TEST_CIPHER:\n");
//	print_text(VECTOR, 64);
//	printk("CBC128_EXPECTED:\n");
//	print_text(CBC128_EXPECTED, 64);
//	aesenc_decrypt(VECTOR, VECTOR, 64);
//	printk("TEST_DECRYPT:\n");
//	print_text(VECTOR, 64);
/************* AESENC TEST END *************/

/***************************************************************
AES(software) Encryption:

	aes_encrypt(void* src, void* dst, unsigned long length);
	aes_decrypt(void* src, void* dst, unsigned long length);

AESENC(hardware) Encryption:

	aesenc_encrypt(void* src, void* dst, unsigned long length);
	aesenc_decrypt(void* src, void* dst, unsigned long length);
****************************************************************/


	if (!(vpage1 & vpage2)) {
		pr_err("crypto-test: Could not get free pages\n");
        return 0;
	}
	
	rdtscll(s_time);
	memcpy((unsigned char *)vpage1, (unsigned char *)vpage2, 2097152);
	rdtscll(e_time);
	printk("crypto-test: memcpy time: %ld cycles.\n", e_time - s_time);
	
	rdtscll(s_time);
	aes_encrypt((unsigned char *)vpage1, (unsigned char *)vpage2, 2097152);
	rdtscll(e_time);
	printk("crypto-test: aes_enc time: %ld cycles.\n", e_time - s_time);
		
	rdtscll(s_time);
	aes_decrypt((unsigned char *)vpage1, (unsigned char *)vpage2, 2097152);
	rdtscll(e_time);
	printk("crypto-test: aes_dec time: %ld cycles.\n", e_time - s_time);
	
	rdtscll(s_time);
	aesenc_encrypt((unsigned char *)vpage1, (unsigned char *)vpage2, 2097152);
	rdtscll(e_time);
	printk("crypto-test: aesenc_enc time: %ld cycles.\n", e_time - s_time);

	rdtscll(s_time);
	aesenc_decrypt((unsigned char *)vpage1, (unsigned char *)vpage2, 2097152);
	rdtscll(e_time);
	printk("crypto-test: aesenc_dec time: %ld cycles.\n", e_time - s_time);

	free_pages(vpage1, 9);
	free_pages(vpage2, 9);

	return 0;
}

static void exit_crypto(void)
{

}

module_init(init_crypto);
module_exit(exit_crypto);

MODULE_LICENSE("GPL");
