/*
    x86-gen.h -- Prototypes for x86 gadget searching functions
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

#ifndef x86GEN_H
#define x86GEN_H

#include "xrop.h"

// unsigned int, char *, size_t, int, size_t
// Generate the x86 gadgets in the given buffer
gadget_list * generate_x86(unsigned long long vma, char * rawbuf, size_t size, int bits, size_t depth, char ** re);

#endif
