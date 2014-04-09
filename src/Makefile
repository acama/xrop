CC=gcc
APP=../build/xropbin
CFLAGS= -Wall -Llibxdisasm/build/lib/ -lxdisasm -lbfd -ggdb

default: all

all: getlib makelib xropbin

withstatic: getlib makelibwithstatic xdisasm

getlib:
		test -d libxdisasm || git clone git@github.com:acama/libxdisasm.git

makelib:
	cd libxdisasm && $(MAKE)
	cp libxdisasm/build/lib/libxdisasm.so ../build/lib/libxdisasm.so

makelibwithstatic:
	cd libxdisasm && $(MAKE) withstatic 
	cp libxdisasm/build/lib/libxdisasm.so ../build/lib/libxdisasm.so

xropbin: main.o xrop.o
	$(CC) $(CFLAGS) -o ${APP} main.o xrop.o

clean:
	rm -rf *.o ${APP}
	rm -rf libxdisasm
