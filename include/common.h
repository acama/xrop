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
#include <capstone/capstone.h>


// insn_list ** -> void
// Print all the instructions in the list
void print_gadgets_list(insn_list **ilist);

// insn_t, int -> int
// Check if the given instruction is a valid instruction
// and/or was decoded sucessfully
int is_valid_instr(insn_t * i, int arch);

// insn_t * -> int
// Is the instruction an unconditional branch
int is_branch(insn_t * i, int arch);

// insn_t * -> void
// Print a gadget in a formatted way
void print_gadget(cs_insn * ins, int type, int isthumb);

// insn_t *, int, int -> void
// Print the path with the given output option
void print_path(insn_t * path[], int pathlen, int output);

// insn_t -> void
// Free the memory
void free_instr(insn_t *i);

// insn_list ** -> void
// Free the memory
// Dirty
void free_all_instrs(insn_list **ilist);

// insn_t * -> void
// Print instruction in a formatted way
void print_instr(insn_t * ins);

// insn_list ** -> void
// Print all the instructions in a formatted way
void print_all_instrs(insn_list **ilist);

// insn_list ** -> size_t
// Count the number of instructions in the list
size_t instr_num(insn_list **ilist);

// insn_t *, insn_list ** -> void
// Initialize list
void init_list(insn_t *i, insn_list **ilist);

// insn_t *, insn_list ** -> void
// Prepend instruction to list
void prepend_instr(insn_t * i, insn_list **ilist);
// insn_t *, insn_list ** -> void
// Append instruction to list
void append_instr(insn_t * i, insn_list **ilist);

#endif
