C=gcc
CFLAGS=-g -pedantic -std=gnu17 -Wall -Wextra
LDFLAGS=-pthread -l crypto

.PHONY: all
all: nyufile

nyufile: nyufile.o

nyufile.o: nyufile.c fsinfo.h linkedlist.h

.PHONY: clean
clean:
	rm -f *.o nyufile
