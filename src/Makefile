CC=gcc
APP=../xrop
LDFLAGS= -Llibxdisasm/build/lib/ -lxdisasm -ldl
BINUTILS = libxdisasm/src/binutils
BFD = $(BINUTILS)/bfd/
CFLAGS := -I$(BFD) -I$(BINUTILS)/include -O3 -Wall -Werror -Wl,-R,'$$ORIGIN/lib/'

default: all

all: makelib xropbin

makelib:
	cd libxdisasm && $(MAKE)
	cp libxdisasm/build/lib/libxdisasm.so ../lib/libxdisasm.so

xropbin: main.o xrop.o x86-gen.o common.o arm-gen.o mips-gen.o ppc-gen.o riscv-gen.o sh4-gen.o
	$(CC) $(CFLAGS) xrop.o main.o common.o x86-gen.o arm-gen.o mips-gen.o ppc-gen.o riscv-gen.o sh4-gen.o -o ${APP} $(LDFLAGS)
	strip -s ${APP}

clean:
	rm -rf *.o ${APP}
	cd libxdisasm && $(MAKE) clean
