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
//#include "../src/libxdisasm/include/xdisasm.h"

#include <capstone/capstone.h>


// Sizes
#define DEFAULT_DEPTH 4
#define MIPS_DEFAULT_DEPTH 8
#define PPC_DEFAULT_DEPTH 8
#define MAX_DEPTH 20
#define X86MAX_INSTR_SIZE 15
#define MAX_GADGET_LEN 100
#define ARM_INSTR_SIZE 4
#define MIPS_INSTR_SIZE 4
#define PPC_INSTR_SIZE 4

// Instruction output function macros
#define BEG_OUTPUT 2
#define MID_OUTPUT 0
#define END_OUTPUT 1
#define SPECIAL_OUTPUT 3
#define THUMB_INSTR 1
#define NORM_INSTR 0 

// instruction structure
typedef struct insn_t{
    unsigned long long vma;
    size_t instr_size;
    char * opcodes;
    char * decoded_instrs;
}insn_t;

// list container for instruction
typedef struct insn_list{
    insn_t * instr;
    struct insn_list * next;
}insn_list;

typedef insn_list ropgadget;

typedef struct gadget_list{
    ropgadget * gdt;
    struct gadget_list * next;
}gadget_list;

typedef struct x86_node_t{
    cs_insn * insn;
    struct x86_node_t * children[X86MAX_INSTR_SIZE];
}x86_node_t;

typedef struct thumb_node_t{
    cs_insn * insn;
    struct thumb_node_t * left;     // instruction of size 2
    struct thumb_node_t * right;    // instruction of size 4
}thumb_node_t;


typedef struct gadgets{
    union ggt{
        gadget_list list;
        x86_node_t * x86_list;
        thumb_node_t thumb_list;
    }ggt;
    void (* print)();
    void (* cprint)();

}gadgets;


gadget_list * gadget_search(unsigned long long vma, char * rawbuf, size_t size, int arch, int bits, int endian, size_t depth);

#endif
