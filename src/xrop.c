/*
    xrop.c -- Gadget searching and printing
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
#include "../include/x86-gen.h"
#include "../include/arm-gen.h"
#include "../include/mips-gen.h"
#include "../include/ppc-gen.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>


// unsigned int, char *, size_t, int, int, int, size_t
// Search for gadgets in given buffer
gadget_list * gadget_search(unsigned long long vma, char * rawbuf, size_t size, int arch, int bits, int endian, size_t depth){
    gadget_list * l = NULL;

    if(arch == ARCH_x86){
        l = generate_x86(vma, rawbuf, size, bits, depth); 
    }else if(arch == ARCH_arm){
        l = generate_arm(vma, rawbuf, size, bits, endian, depth);
    }else if(arch == ARCH_powerpc){ 
        l = generate_powerpc(vma, rawbuf, size, bits, endian, depth);
    }else if(arch == ARCH_mips){ 
        l = generate_mips(vma, rawbuf, size, bits, endian, depth);
    }

    return l;
}
