C=gcc
CFLAGS=-g -pedantic -std=gnu17 -Wall -Wextra
LDFLAGS=-pthread

.PHONY: all
all: nyufile

nyufile: nyufile.o

nyufile.o: nyufile.c fsinfo.h

.PHONY: clean
clean:
	rm -f *.o nyufile

