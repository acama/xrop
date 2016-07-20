/*
    sh4-gen.c -- Gadget searching for SH4
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
// Is the buffer pointing to a SH4 gadget end sequence
int is_sh4_end(uint16_t * rawbuf, int bits, int endian){
    int acc = 0;
    uint16_t ins;

    if(!rawbuf) return 1;

    ins = rawbuf[0];
    if(bits)
        ins = ins >> 8 | ins << 8; // reverse since little endian

    acc = (ins == 0xb); //rts
    acc |= (BITS(ins, 7, 0) == 0xb  && BITS(ins, 15, 12) == 4); //jsr @rn
    acc |= (BITS(ins, 7, 0) == 0x2b  && BITS(ins, 15, 12) == 4); //jmp @rn
    acc |= (BITS(ins, 7, 0) == 3  && BITS(ins, 15, 12) == 0); //bsrf rn
    acc |= (BITS(ins, 15, 12) == 10); //braf rn

    return acc;
}

// unsigned int, char *, size_t, int, int, size_t
// Generate all the SH4 gadgets
gadget_list * generate_sh4(unsigned long long vma, char * rawbuf, size_t size, int bits, int endian, size_t depth, char **re){
    insn_t * it;
    unsigned int i = 0, j = 0;
    uint16_t * sh4buf = (uint16_t *) rawbuf;
    size_t nsize_sh4 = size / 2;

    for(i = 0; i < nsize_sh4; i++){
        if(is_sh4_end(&sh4buf[i], bits, endian)){
            insn_list * gadget = NULL;
            it = disassemble_one(vma + i * SH4_INSTR_SIZE, (char *)&sh4buf[i], SH4_INSTR_SIZE, ARCH_sh4, bits, endian);
            if(!is_valid_instr(it, ARCH_sh4)) continue;
            prepend_instr(it, &gadget);
            it = disassemble_one(vma + i * SH4_INSTR_SIZE + SH4_INSTR_SIZE, (char *)&sh4buf[i + 1], SH4_INSTR_SIZE, ARCH_sh4, bits, endian);
            append_instr(it, &gadget);
            for(j = 1; j < depth; j++){
                char * iptr = (char *)&sh4buf[i] - (j * 2);
                unsigned int nvma = (vma + i * 2) - (j * 2);
                if(nvma < vma) break;
                it = disassemble_one(nvma, iptr, SH4_INSTR_SIZE, ARCH_sh4, bits, endian);
                if(!is_valid_instr(it, ARCH_sh4) 
                        || is_sh4_end((uint16_t *)iptr, bits, endian) 
                        || is_branch(it, ARCH_sh4)) break;
                prepend_instr(it, &gadget);
            }
            print_gadgets_list_delay(&gadget, re, 1);
            free_all_instrs(&gadget);
        }
    }

    return NULL;
}
