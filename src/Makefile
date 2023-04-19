CC=gcc
APP=../xrop
LDFLAGS= -Llibxdisasm/build/lib/ -lxdisasm -ldl
BINUTILS = libxdisasm/src/binutils
BFD = $(BINUTILS)/bfd/
CFLAGS := -I$(BFD) -I$(BINUTILS)/include -O3 -Wall -Werror 
UNAME := $(shell uname)

# Set the appropriate flag based on the host OS
ifeq ($(UNAME), Linux)
  RPATH = -Wl,-rpath,'$$ORIGIN/lib/'
  STRIP_FLAGS = -s
else ifeq ($(UNAME), Darwin)
  RPATH = -Wl,-rpath,@executable_path/lib
  INSTALL_NAME = install_name_tool -change libxdisasm.so @executable_path/lib/libxdisasm.so ${APP}
  STRIP_FLAGS = -x
endif


default: all

all: makelib xropbin

makelib:
	cd libxdisasm && $(MAKE)
	cp libxdisasm/build/lib/libxdisasm.so ../lib/libxdisasm.so

xropbin: main.o xrop.o x86-gen.o common.o arm-gen.o mips-gen.o ppc-gen.o riscv-gen.o sh4-gen.o sparc-gen.o color_print.o
	$(CC) $(CFLAGS) $(RPATH) xrop.o main.o common.o x86-gen.o arm-gen.o mips-gen.o ppc-gen.o riscv-gen.o sh4-gen.o sparc-gen.o color_print.o -o ${APP} $(LDFLAGS)
	$(INSTALL_NAME)
	strip $(STRIP_FLAGS) ${APP}

clean:
	rm -rf *.o ${APP}
	cd libxdisasm && $(MAKE) clean
