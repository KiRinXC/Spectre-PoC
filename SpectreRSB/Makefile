CC = gcc
CFLAGS += --static -O0 -fno-prefetch-loop-arrays  -fno-stack-protector -fcf-protection=none -fno-omit-frame-pointer -I ../tools/
CSRC = $(shell find $(abspath ./) $(abspath ../tools/) -name "*.c" -or -name "*.S" -or -name "*.cpp")

all:
	$(CC) $(CFLAGS) $(CSRC) -o PoC

clean:
	rm PoC
