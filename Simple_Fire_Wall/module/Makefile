########Makefile for Simple IP FireWall##############
######### test On Debian 4.0rc3 ##############


sipfw_module-objs := sipfw_k.o sipfw_k_file.o sipfw_k_proc.o sipfw_k_nl.o sipfw_k_common.o
obj-m := sipfw_module.o
#sipfw_k_file.o

KERNELDIR = /lib/modules/`uname -r`/build

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
	rm -rf *.mod.c Module.symvers *.mod.o *.o .*.cmd .tmp_versions 
install:
	insmod $(TARGET).ko
uninstall:
	rmmod $(TARGET).ko
clean:
	rm -rf *.o *.mod.c *.ko 
	rm -rf Module.symvers .*cmd .tmp_versions
