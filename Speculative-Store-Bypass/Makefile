CC = gcc
CFLAGS += -O2 -fno-prefetch-loop-arrays -I ../tools/
CSRC = $(shell find $(abspath ./) $(abspath ../tools/) -name "*.c" -or -name "*.S" -or -name "*.cpp")

all:
	$(CC) $(CFLAGS) $(CSRC) -o PoC

clean:
	rm PoC
