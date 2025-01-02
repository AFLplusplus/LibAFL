obj-m += harness.o

all:
	make -C /lib/modules/$(LINUX_MODULES)/build M=$(PWD) modules
	gcc -Wall -Werror -o user user.c

clean:
	make -C /lib/modules/$(LINUX_MODULES)/build M=$(PWD) clean
	rm -f user