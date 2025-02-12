obj-m += harness.o
# harness-objs += symfinder.o

all:
	make EXTRA_CFLAGS="-DUSE_LQEMU=1" -C /lib/modules/$(LINUX_MODULES)/build M=$(PWD) modules
	gcc -Wall -Werror -o user user.c

nyx:
	make EXTRA_CFLAGS="-DUSE_NYX=1" -C /lib/modules/$(LINUX_MODULES)/build M=$(PWD) modules
	gcc -Wall -Werror -o user user.c

clean:
	make -C /lib/modules/$(LINUX_MODULES)/build M=$(PWD) clean
	rm -f user