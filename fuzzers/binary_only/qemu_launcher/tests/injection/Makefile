all: static sqltest

sqltest:	sqltest.c
	gcc -g -o sqltest sqltest.c -l sqlite3 -lm -lpthread 

static:	sqltest.c
	gcc -g -o static sqltest.c -l sqlite3 -lm -static -lpthread -ldl

fuzz:	sqltest.c
	afl-clang-fast -o fuzz sqltest.c -l sqlite3

clean:
	rm -f sqltest static fuzz
