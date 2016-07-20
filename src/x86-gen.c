/*
    x86-gen.c -- Gadget searching for x86
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

// char *, int
// Check if the given buffer is pointing to gadget-end sequence
int is_x86_end(char * rawbuf, int bits){
    int acc;

    if(!rawbuf)
        return 0;

    acc = ((unsigned short *)rawbuf)[0] == (unsigned short)0x80cd // int 80h 
            || ((unsigned short *)rawbuf)[0] == (unsigned short)0x340f // sysenter
            || rawbuf[0] == (char) 0xc3 // ret
            || rawbuf[0] == (char) 0xc2 // retn
            || (((((unsigned short *)rawbuf)[0] & 0xF0FF) == 0xD0FF) && 
                    ((((unsigned short *)rawbuf)[0] & 0xFFFF) <= 0xD7FF)) // call reg
            || (((((unsigned short *)rawbuf)[0] & 0xF0FF) == 0x10FF) 
                    && ((((unsigned short *)rawbuf)[0] & 0xFFFF) <= 0x17FF)) // call [reg]
            || (((((unsigned short *)rawbuf)[0] & 0xF0FF) == 0x50FF) 
                    && ((((unsigned short *)rawbuf)[0] & 0xFFFF) <= 0x57FF)) // call [reg + 8]
            || (((((unsigned short *)rawbuf)[0] & 0xF0FF) == 0x90FF) 
                    && ((((unsigned short *)rawbuf)[0] & 0xFFFF) <= 0x97FF)) // call [reg + 32]
            || (((((unsigned short *)rawbuf)[0] & 0xF0FF) == 0xE0FF) && 
                    ((((unsigned short *)rawbuf)[0] & 0xFFFF) <= 0xE7FF)) // jmp reg
            || (((((unsigned short *)rawbuf)[0] & 0xF0FF) == 0x20FF) 
                    && ((((unsigned short *)rawbuf)[0] & 0xFFFF) <= 0x27FF)) // jmp [reg]
            || (((((unsigned short *)rawbuf)[0] & 0xF0FF) == 0x60FF) 
                    && ((((unsigned short *)rawbuf)[0] & 0xFFFF) <= 0x67FF)) // jmp [reg + 8]
            || (((((unsigned short *)rawbuf)[0] & 0xF0FF) == 0xA0FF) 
                    && ((((unsigned short *)rawbuf)[0] & 0xFFFF) <= 0xA7FF)); // jmp [reg + 32]
    
    if(bits == 64){
        acc |= ((unsigned short *) rawbuf)[0] == 0x050f // syscall
            || (((((unsigned short *)rawbuf)[0] & 0xF0FFFF) == 0xD0FF41) 
                    && ((((unsigned short *)rawbuf)[0] & 0xFFFFFF) <= 0xD7FF41)) // call re
            || (((((unsigned short *)rawbuf)[0] & 0xF0FFFF) == 0x10FF41) 
                    && ((((unsigned short *)rawbuf)[0] & 0xFFFFFF) <= 0x17FF41) // call [reg]
                    && ((((unsigned short *)rawbuf)[0] & 0xFFFFFF) != 0x15FF41)) // this opcode one is invalid
            || (((((unsigned short *)rawbuf)[0] & 0xF0FFFF) == 0x50FF41) 
                    && ((((unsigned short *)rawbuf)[0] & 0xFFFFFF) <= 0x57FF41)) // call [reg + 8]
            || (((((unsigned short *)rawbuf)[0] & 0xF0FFFF) == 0x90FF41) 
                    && ((((unsigned short *)rawbuf)[0] & 0xFFFFFF) <= 0x97FF41)) // call [reg + 32]
            || (((((unsigned short *)rawbuf)[0] & 0xF0FFFF) == 0xE0FF41) && 
                    ((((unsigned short *)rawbuf)[0] & 0xFFFFFF) <= 0xE7FF41)) // jmp reg
            || (((((unsigned short *)rawbuf)[0] & 0xF0FFFF) == 0x20FF41) 
                    && ((((unsigned short *)rawbuf)[0] & 0xFFFFFF) <= 0x27FF41)) // jmp [reg]
            || (((((unsigned short *)rawbuf)[0] & 0xF0FFFF) == 0x60FF41) 
                    && ((((unsigned short *)rawbuf)[0] & 0xFFFFFF) <= 0x67FF41)) // jmp [reg + 8]
            || (((((unsigned short *)rawbuf)[0] & 0xF0FFFF) == 0xA0FF41) 
                    && ((((unsigned short *)rawbuf)[0] & 0xFFFFFF) <= 0xA7FF41)); // jmp [reg + 32]
    }

    return acc;
}

// char *, int
// Check if the given buffer is pointing to a search stoppger (a.k.a ret)
int is_x86_stop(char * rawbuf, int bits){

    if(!rawbuf)
        return 0;
 
    return rawbuf[0] == (char) 0xc3; // ret
}

// x86_node_t *, char *, char *, size_t, size_t, size_t, int, size_t
// Generate all the gadgets connected to the x86 node
void get_children_x86(x86_node_t * currnode, char * begptr, char * rawbuf, unsigned long long lowervma, size_t bufsize, int bits, size_t depth){
    int i = 0;
    insn_t * it = NULL, * curr = NULL;
    unsigned long long rvma = 0;
    it = currnode->insn;

    for(i = 1; i < (X86MAX_INSTR_SIZE) && depth > 0; i++){
        char * nrawbuf = rawbuf - i;
        rvma = it->vma - i;
        if(nrawbuf < begptr) break;
        if(rvma < lowervma) break;
        if(is_x86_stop(nrawbuf, bits)) break;
        
        curr = disassemble_one(rvma, nrawbuf, bufsize + i, ARCH_x86, bits, 0);
        if(is_branch(curr, ARCH_x86)) break;
        if(is_valid_instr(curr, ARCH_x86) && (curr->instr_size == i)){
            x86_node_t * tmpn = malloc(sizeof(x86_node_t));
            if(!tmpn){
                perror("malloc");
                exit(-1);
            }
            memset(tmpn, 0, sizeof(x86_node_t));
            tmpn->insn = curr;
            currnode->children[i] = tmpn;
            get_children_x86(tmpn, begptr, nrawbuf, lowervma, bufsize + i, bits, depth - 1);
        }
    }
}

// x86_node_t *, insn_t *, size_t, int
// Recursively print the gadgets in the x86 trie
void r_print_gadgets_trie(x86_node_t * n, insn_t * path[], size_t depth, int pathlen, char ** re){
    int i = 0;
    x86_node_t * tmp = NULL;   
    int acc = 1;

    path[pathlen] = n->insn;
 
    if((int) depth < 0){
        return;
    }
    
    for(i = 0; i < X86MAX_INSTR_SIZE; i++){
        tmp = n->children[i];
        if(tmp){
            acc = 0;
            r_print_gadgets_trie(tmp, path, depth - 1, pathlen + 1, re);
        }
    }

    if(acc){
        print_path(path, pathlen, NORM_INSTR, re);
    }

}

// x86_node_t *, size_t
// Print the gadgets in the x86 trie
void print_gadgets_trie(x86_node_t * n, size_t depth, char ** re){
    insn_t * path[MAX_GADGET_LEN] = {0};
    r_print_gadgets_trie(n, path, depth, 0, re);
}

// unsigned int, char *, size_t, int, size_t
// Generate the x86 gadgets in the given buffer
gadget_list * generate_x86(unsigned long long vma, char * rawbuf, size_t size, int bits, size_t depth, char ** re){
    insn_t * it = NULL;
    unsigned long long  i = 0;
    unsigned long long rvma = 0;
    x86_node_t * retrootn = NULL;
    
    // Find all ret instructions
    for(; i < size; i++){
        if(is_x86_end((rawbuf + i), bits)){
            retrootn = malloc(sizeof(x86_node_t));
            if(!retrootn){
                perror("malloc");
                exit(-1);
            }
            memset(retrootn, 0, sizeof(x86_node_t));

            rvma = vma + i;
            it = disassemble_one(rvma, rawbuf + i, X86MAX_INSTR_SIZE, ARCH_x86, bits, 0);
            retrootn->insn = it;
            get_children_x86(retrootn, rawbuf, rawbuf + i, vma, size - i, bits, depth);

            print_gadgets_trie(retrootn, depth, re);
        }

    }

    return NULL;
}
