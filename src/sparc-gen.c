/*
    sparc-gen.c -- Gadget searching for SPARC
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
// Is the buffer pointing to a SPARC gadget end sequence
int is_sparc_end(uint32_t * rawbuf, int bits, int endian){
    int acc = 0;
    uint32_t ins;

    if(!rawbuf) return 1;

    ins = rawbuf[0];

    if(endian){
        acc = (ins == 0x08e0c781);
        acc |= (ins == 0x08e0c381);
    }else{
        acc = (ins == 0x81c7e008);
        acc |= (ins == 0x81c3e008);
    }

    return acc;
}

// unsigned int, char *, size_t, int, int, size_t
// Generate all the SPARC gadgets
gadget_list * generate_sparc(unsigned long long vma, char * rawbuf, size_t size, int bits, int endian, size_t depth, char **re){
    insn_t * it;
    unsigned int i = 0, j = 0;
    uint32_t * sparcbuf = (uint32_t *) rawbuf;
    size_t nsize_sparc = size / 4;

    for(i = 0; i < nsize_sparc; i++){
        if(is_sparc_end(&sparcbuf[i], bits, endian)){
            insn_list * gadget = NULL;
            it = disassemble_one(vma + i * 4, (char *)&sparcbuf[i], SPARC_INSTR_SIZE, ARCH_sparc, bits, endian);
            if(!is_valid_instr(it, ARCH_sparc)) continue;
            prepend_instr(it, &gadget);
            it = disassemble_one(vma + i * SPARC_INSTR_SIZE + SPARC_INSTR_SIZE, (char *)&sparcbuf[i + 1], SPARC_INSTR_SIZE, ARCH_sparc, bits, endian);
            append_instr(it, &gadget);
            for(j = 1; j < depth; j++){
                char * iptr = (char *)&sparcbuf[i] - (j * 4);
                unsigned int nvma = (vma + i * 4) - (j * 4);
                if(nvma < vma) break;
                it = disassemble_one(nvma, iptr, SPARC_INSTR_SIZE, ARCH_sparc, bits, endian);
                if(!is_valid_instr(it, ARCH_sparc) 
                        || is_sparc_end((uint32_t *)iptr, bits, endian) 
                        || is_branch(it, ARCH_sparc)) break;
                prepend_instr(it, &gadget);
            }
            print_gadgets_list_delay(&gadget, re, 1);
            free_all_instrs(&gadget);
        }
    }

    return NULL;
}
