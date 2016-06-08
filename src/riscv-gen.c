/*
    riscv-gen.c -- Gadget searching for RISCV
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
// Is the buffer pointing to a RISCV gadget end sequence
int is_riscv_end(uint32_t * rawbuf, int bits, int endian){
    int acc = 0;
    uint32_t ins;

    if(!rawbuf) return 1;

    ins = rawbuf[0];

    if(!endian){
        acc = (ins == 0x00008067);
    }else{
        acc = (ins == 0x67800000);
    }

    return acc;
}

// unsigned int, char *, size_t, int, int, size_t
// Generate all the RISCV gadgets
gadget_list * generate_riscv(unsigned long long vma, char * rawbuf, size_t size, int bits, int endian, size_t depth, char **re){
    insn_t * it;
    unsigned int i = 0, j = 0;
    uint32_t * riscvbuf = (uint32_t *) rawbuf;
    size_t nsize_riscv = size / 4;

    for(i = 0; i < nsize_riscv; i++){
        if(is_riscv_end(&riscvbuf[i], bits, endian)){
            insn_list * gadget = NULL;
            it = disassemble_one(vma + i * 4, (char *)&riscvbuf[i], RISCV_INSTR_SIZE, ARCH_riscv, bits, endian);
            if(!is_valid_instr(it, ARCH_riscv)) continue;
            prepend_instr(it, &gadget);
            for(j = 1; j < depth; j++){
                char * iptr = (char *)&riscvbuf[i] - (j * 4);
                unsigned int nvma = (vma + i * 4) - (j * 4);
                if(nvma < vma) break;
                it = disassemble_one(nvma, iptr, RISCV_INSTR_SIZE, ARCH_riscv, bits, endian);
                if(!is_valid_instr(it, ARCH_riscv) 
                        || is_riscv_end((uint32_t *)iptr, bits, endian) 
                        || is_branch(it, ARCH_riscv)) break;
                prepend_instr(it, &gadget);
            }
            print_gadgets_list(&gadget, re);
            free_all_instrs(&gadget);
        }
    }

    return NULL;
}
