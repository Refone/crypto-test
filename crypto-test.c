#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/crypto.h>
#include "crypto.h"


static const unsigned char KEY[] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
									  0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};

static AES_KEY key;

extern void AESENC_Key_Expansion(const unsigned char* userkey,
								 AES_KEY* key_schedule);

extern void AESENC_encrypt (const unsigned char *in,
							unsigned char *out,
							unsigned char ivec[16],
							unsigned long length,
							const unsigned char *KS,
							int nr);

extern void AESENC_decrypt (const unsigned char *in,
							unsigned char *out,
							unsigned char ivec[16],
							unsigned long length,
							const unsigned char *KS,
							int nr);

static int init_crypto(void)
{
	printk("crypto module init.\n");
	AESENC_Key_Expansion(KEY, &key);	

	return 0;
}

static void exit_crypto(void)
{

}

module_init(init_crypto);
module_exit(exit_crypto);

MODULE_LICENSE("GPL");
