API := ${HARNESS_API}

obj-m += harness.o

harness-objs := x509_harness.o
harness-objs += vharness/src/calls.o
harness-objs += vharness/src/lqemu.o
harness-objs += vharness/src/vharness_api.o
# harness-y += vharness/src/vharness.o

ccflags-y := -I$(PWD)/vharness/include
ccflags-y += -DUSE_$(API)

all: harness user

harness: x509_harness.c vharness/src/calls.c vharness/src/lqemu.c vharness/src/vharness_api.c vharness/src/vharness.c
	make -C /lib/modules/$(LINUX_MODULES)/build M=$(PWD)

user: user.c
	gcc -Wall -Werror -o user user.c

clean:
	make -C /lib/modules/$(LINUX_MODULES)/build M=$(PWD) clean
	rm -f user

.PHONE: clean
