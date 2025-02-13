#
# american fuzzy lop++ - libqasan
# -------------------------------
#
# Written by Andrea Fioraldi <andreafioraldi@gmail.com>
#
# Copyright 2019-2020 Andrea Fioraldi. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#   http://www.apache.org/licenses/LICENSE-2.0
#

OUT_DIR     ?= .

override CFLAGS      += -Wno-int-to-void-pointer-cast -ggdb -O1 -fno-builtin -Wno-unused-result
override LDFLAGS     += -ldl -pthread

SRC := libqasan.c hooks.c malloc.c mmap.c string.c uninstrument.c patch.c dlmalloc.c printf/printf.c
HDR := libqasan.h qasan.h map_macro.h printf/printf.h

all: $(OUT_DIR)/libgasan.so $(OUT_DIR)/libqasan.so

$(OUT_DIR)/libgasan.so: $(HDR) $(SRC)
	$(CC) $(CFLAGS) -DASAN_GUEST=1 -fPIC -shared $(SRC) -o $@ $(LDFLAGS)

$(OUT_DIR)/libqasan.so: $(HDR) $(SRC)
	$(CC) $(CFLAGS) -fPIC -shared $(SRC) -o $@ $(LDFLAGS)

.NOTPARALLEL: clean

clean:
	rm -f *.o *.so *~ a.out core core.[1-9][0-9]*
	rm -f $(OUT_DIR)/libgasan.so
	rm -f $(OUT_DIR)/libqasan.so
