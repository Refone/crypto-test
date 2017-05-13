#if !defined (ALIGN16)
# if defined (__GNUC__)
# define ALIGN16 __attribute__((aligned(16)))
# else
# define ALIGN16 __declspec(align(16))
# endif
#endif

typedef struct KEY_SCHEDULE{
	ALIGN16 unsigned char KEY[16*15];
	unsigned int nr;
}AES_KEY;

