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
#include "../include/riscv-gen.h"
#include "../include/sh4-gen.h"
#include "../include/sparc-gen.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>


// unsigned int, char *, size_t, int, int, int, size_t
// Search for gadgets in given buffer
gadget_list * gadget_search(char * rawbuf, size_t size, config_t * cfg){
    gadget_list * l = NULL;

    switch(cfg->arch){
        case ARCH_x86:
            l = generate_x86(cfg->vma, rawbuf, size, cfg->bits, cfg->depth, cfg->re); 
            break;
        case  ARCH_arm:
            l = generate_arm(cfg->vma, rawbuf, size, cfg->bits, cfg->endian, cfg->depth, cfg->re);
            break;
        case ARCH_powerpc:
            l = generate_powerpc(cfg->vma, rawbuf, size, cfg->bits, cfg->endian, cfg->depth, cfg->re);
            break;
        case ARCH_mips:
            l = generate_mips(cfg->vma, rawbuf, size, cfg->bits, cfg->endian, cfg->depth, cfg->re);
            break;
        case ARCH_riscv:
            l = generate_riscv(cfg->vma, rawbuf, size, cfg->bits, cfg->endian, cfg->depth, cfg->re);
            break;
        case ARCH_sh4:
            l = generate_sh4(cfg->vma, rawbuf, size, cfg->bits, cfg->endian, cfg->depth, cfg->re);
            break;
        case ARCH_sparc:
            l = generate_sparc(cfg->vma, rawbuf, size, cfg->bits, cfg->endian, cfg->depth, cfg->re);
            break;
    }

    return l;
}
