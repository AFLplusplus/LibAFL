CC ?= gcc
CFLAGS += -Ofast -fPIC -fvisibility=hidden -finline-functions
LDFLAGS =

ifneq ($(origin NO_LTO), environment)
	CFLAGS += -flto
	LDFLAGS += -flto
endif

PREFIX ?= /usr

ODIR=build
SDIR=src

_OBJ = cfg.o disassembler.o tnt_cache.o decoder.o libxdc.o mmh3.o trace_cache.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

default: libxdc.so libxdc.a ptdump ptdump_static

$(ODIR)/%.o: $(SDIR)/%.c $(SDIR)/*.h libxdc.h
	mkdir -p build
	$(CC) -c -o $@ $< $(CFLAGS)

libxdc.so: $(OBJ)
	$(CC) $^ -o $@ -shared $(CFLAGS) $(LDFLAGS) -L../capstone_v4/ -l:libcapstone.so.4

libxdc.a: $(OBJ)
	$(AR) rcs $@ $^

ptdump: libxdc.so test/*.c test/*.h
	$(CC) test/ptdump.c test/page_cache.c test/helper.c -o build/$@ -Itest/ -I./ -Lbuild/ $(CFLAGS) $(LDFLAGS) -L. -lxdc -L../capstone_v4/ -l:libcapstone.so.4

ptdump_static: libxdc.a test/*.c test/*.h
	$(CC) test/ptdump.c test/page_cache.c test/helper.c -o build/$@ -Itest/ -I./ $(CFLAGS) $(LDFLAGS) -L. -l:libxdc.a -L../capstone_v4/ -l:libcapstone.a

tester_dyn: libxdc.so test/*.c test/*.h
	$(CC) test/tester.c test/page_cache.c test/helper.c -o $@ -Itest/ -I./ $(CFLAGS) $(LDFLAGS) -L. -lxdc -L../capstone_v4/ -l:libcapstone.so.4

tester_static: libxdc.a test/*.c test/*.h
	$(CC) test/tester.c test/page_cache.c test/helper.c -o $@ -Itest/ -I./ $(CFLAGS) $(LDFLAGS) -L. -l:libxdc.a -L../capstone_v4/ -l:libcapstone.a

install: libxdc.so libxdc.a ptdump
	mkdir -p $(PREFIX)/include $(PREFIX)/lib
	install -m0644 libxdc.h $(PREFIX)/include/
	install -m0755 libxdc.so $(PREFIX)/lib/
	install -m0755 libxdc.a $(PREFIX)/lib/
	install -m0755 build/ptdump $(PREFIX)/bin/

.PHONY: clean install

clean:
	rm -f $(ODIR)/*.o build/*
	rm -f libxdc.so
	rm -f libxdc.a
