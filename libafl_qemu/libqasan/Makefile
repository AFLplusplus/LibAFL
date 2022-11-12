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

CFLAGS      += -Wno-int-to-void-pointer-cast -ggdb
LDFLAGS     += -ldl -pthread

SRC := libqasan.c hooks.c malloc.c string.c uninstrument.c patch.c dlmalloc.c
HDR := libqasan.h

all: libqasan.so

libqasan.so: $(HDR) $(SRC)
	$(CC) $(CFLAGS) -fPIC -shared $(SRC) -o $(OUT_DIR)/$@ $(LDFLAGS)

.NOTPARALLEL: clean

clean:
	rm -f *.o *.so *~ a.out core core.[1-9][0-9]*
	rm -f libqasan.so
