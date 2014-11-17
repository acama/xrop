CC=gcc
APP=../xrop
CFLAGS= -Wall
LDFLAGS= -lbfd -liberty -lz -ldl -lcapstone

default: all

all: xropbin

xropbin: main.o xrop.o x86-gen.o common.o arm-gen.o mips-gen.o ppc-gen.o
	$(CC) $(CFLAGS) xrop.o main.o common.o x86-gen.o arm-gen.o mips-gen.o ppc-gen.o -o ${APP} $(LDFLAGS)

clean:
	rm -rf *.o ${APP}
