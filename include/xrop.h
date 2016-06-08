/*
    xrop.h -- structs, defines and prototypes 
    Copyright (C) 2014  Amat I. Cama

    This file is part of xrop.

    Xrop is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Xrop is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>. 
 
*/
#ifndef XROP_H
#define XROP_H

#include <stdlib.h>
#include "../src/libxdisasm/include/xdisasm.h"


// Sizes
#define DEFAULT_DEPTH 4
#define MIPS_DEFAULT_DEPTH 8
#define RISCV_DEFAULT_DEPTH 8
#define PPC_DEFAULT_DEPTH 8
#define MAX_DEPTH 20
#define X86MAX_INSTR_SIZE 15
#define MAX_GADGET_LEN 100
#define ARM_INSTR_SIZE 4
#define MIPS_INSTR_SIZE 4
#define RISCV_INSTR_SIZE 4
#define PPC_INSTR_SIZE 4

// Instruction output function macros
#define BEG_OUTPUT 2
#define MID_OUTPUT 0
#define END_OUTPUT 1
#define SPECIAL_OUTPUT 3
#define THUMB_INSTR 1
#define NORM_INSTR 0 

// maximum allowed regexes
#define MAX_REGEX 16

typedef insn_list ropgadget;

typedef struct gadget_list{
    ropgadget * gdt;
    struct gadget_list * next;
}gadget_list;

typedef struct x86_node_t{
    insn_t * insn;
    struct x86_node_t * children[X86MAX_INSTR_SIZE];
}x86_node_t;

typedef struct thumb_node_t{
    insn_t * insn;
    struct thumb_node_t * left;     // instruction of size 2
    struct thumb_node_t * right;    // instruction of size 4
}thumb_node_t;

typedef struct config_t{
    unsigned long long vma;
    int arch;
    int bits;
    int endian;
    size_t depth;
    char ** re;
}config_t;

// info on segment start
// and end address
typedef struct seginfo_t{
    unsigned char isset;
    unsigned long long start_addr;
    unsigned long long end_addr;
}seginfo_t;

gadget_list * gadget_search(char * rawbuf, size_t size, config_t * cfg);

#endif
