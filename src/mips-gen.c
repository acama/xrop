/*
    mips-gen.c -- Gadget searching for MIPS
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

#include "../include/xrop.h"
#include "../include/common.h"
#include <string.h>
#include <stdio.h>
#include <stdint.h>



// unint32_t *, int, int -> int
// Is the buffer pointing to a MIPS gadget end sequence
int is_mips_end(uint32_t * rawbuf, int bits, int endian){
    int acc = 0;
    uint32_t ins;

    if(!rawbuf) return 1;

    ins = rawbuf[0];

    if(!endian)
        acc = (ins == 0x03e00008);
    else
        acc = (ins == 0x0800E003);

    return acc;
}

// unsigned int, char *, size_t, int, int, size_t
// Generate all the MIPS gadgets
gadget_list * generate_mips(unsigned long long vma, char * rawbuf, size_t size, int bits, int endian, size_t depth, char **re){
    insn_t * it;
    unsigned int i = 0, j = 0;
    uint32_t * mipsbuf = (uint32_t *) rawbuf;
    size_t nsize_mips = size / MIPS_INSTR_SIZE;

    for(i = 0; i < nsize_mips; i++){
        if(is_mips_end(&mipsbuf[i], bits, endian)){
            insn_list * gadget = NULL;
            it = disassemble_one(vma + i * MIPS_INSTR_SIZE, (char *)&mipsbuf[i], MIPS_INSTR_SIZE, ARCH_mips, bits, endian);
            if(!is_valid_instr(it, ARCH_mips)) continue;
            prepend_instr(it, &gadget);
            it = disassemble_one(vma + i * MIPS_INSTR_SIZE + MIPS_INSTR_SIZE, (char *)&mipsbuf[i + 1], MIPS_INSTR_SIZE, ARCH_mips, bits, endian);
            append_instr(it, &gadget);
            for(j = 1; j < depth; j++){
                char * iptr = (char *)&mipsbuf[i] - (j * MIPS_INSTR_SIZE);
                unsigned int nvma = (vma + i * MIPS_INSTR_SIZE) - (j * MIPS_INSTR_SIZE);
                if(nvma < vma) break;
                it = disassemble_one(nvma, iptr, MIPS_INSTR_SIZE, ARCH_mips, bits, endian);
                if(!is_valid_instr(it, ARCH_mips) 
                        || is_mips_end((uint32_t *)iptr, bits, endian) 
                        || is_branch(it, ARCH_mips)) break;
                prepend_instr(it, &gadget);
            }
            print_gadgets_list_delay(&gadget, re, 1);
            free_all_instrs(&gadget);
        }
    }

    return NULL;
}
