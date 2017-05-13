obj-m += refone.o
refone-objs := crypto-test.o aesenc_asm.o

all:
	    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
