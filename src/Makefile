CC=gcc
APP=../build/xropbin
CFLAGS= -Wall -ggdb
LDFLAGS= -Llibxdisasm/build/lib/ -lbfd -lxdisasm

default: all

all: getlib makelib xropbin

withstatic: getlib makelibwithstatic xropbin

getlib:
	test -d libxdisasm || git clone https://github.com/acama/libxdisasm

makelib:
	cd libxdisasm && $(MAKE)
	cp libxdisasm/build/lib/libxdisasm.so ../build/lib/libxdisasm.so

makelibwithstatic:
	cd libxdisasm && $(MAKE) withstatic 
	cp libxdisasm/build/lib/libxdisasm.so ../build/lib/libxdisasm.so

xropbin: main.o xrop.o x86-gen.o common.o arm-gen.o mips-gen.o ppc-gen.o
	$(CC) $(CFLAGS) xrop.o main.o common.o x86-gen.o arm-gen.o mips-gen.o ppc-gen.o -o ${APP} $(LDFLAGS)

clean:
	rm -rf *.o ${APP}
	rm -rf libxdisasm
