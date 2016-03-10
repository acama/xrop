/*
    arm-gen.h -- prototypes for ARM gadget search functions
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

#ifndef ARMGEN_H
#define ARMGEN_H

#include "xrop.h"

// unsigned int, char *, size_t, int, int, size_t
// Generate all the ARM gadgets
gadget_list * generate_arm(unsigned long long vma, char * rawbuf, size_t size, int bits, int endian, size_t depth, char ** re);

#endif
