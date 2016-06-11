/*
    common.h -- Prototypes for common functions
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

#ifndef COMMON_H
#define COMMON_H

#include "xrop.h"

#define BITS(insn, high, low) ((insn >> low) & ((1 << (high - low + 1)) - 1))

// insn_list ** -> void
// Print all the instructions in the list
void print_gadgets_list(insn_list **ilist, char ** re);

// insn_list ** -> void
// Print all the instructions in the list with optional delay
void print_gadgets_list_delay(insn_list **ilist, char ** re, int delay);

// insn_t, int
// Check if the given instruction is a valid instruction
// and/or was decoded sucessfully
int is_valid_instr(insn_t * i, int arch);

// insn_t *
// Is the instruction an unconditional branch
int is_branch(insn_t * i, int arch);

// insn_t * -> void
// Print a gadget in a formatted way
void print_gadget(insn_t * ins, int type, int isthumb);

// insn_t *, int, int
// Print the path with the given output option
void print_path(insn_t * path[], int pathlen, int output, char ** re);

// char *, char * -> int
// perform regex matching on given string with pattern
int reg_match(char * str, char * re);

#endif
