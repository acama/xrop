/*
    arm-gen.c -- Gadget searching for ARM
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

// thumb_node_t *, insn_t *, size_t, int
// Recursively print the gadgets in the Thumb binary tree
void r_print_gadgets_bt(thumb_node_t * n, insn_t * path[], size_t depth, int pathlen, char **re){
    thumb_node_t * tmp = NULL;   

    if(n == NULL) return;
    path[pathlen] = n->insn;
 
    if((int)depth < 0){
        return;
    }

    if((n->left == NULL) && (n->right == NULL)){
        print_path(path, pathlen, THUMB_INSTR, re);
    }

    tmp = n->left;
    if(tmp){
        r_print_gadgets_bt(tmp, path, depth - 1, pathlen + 1, re);
    }
    
    tmp = n->right;
    if(tmp){
        r_print_gadgets_bt(tmp, path, depth - 1, pathlen + 1, re);
    }

}

// thumb_node_t *, size_t
// Print the gadgets in the Thumb binary tree
void print_gadgets_bt(thumb_node_t * n, size_t depth, char **re){
    insn_t * path[MAX_GADGET_LEN] = {0};
    r_print_gadgets_bt(n, path, depth, 0, re);
}


// unint32_t *, int, int -> int
// Is the buffer pointing to a ARM gadget end sequence
int is_arm_end(uint32_t * rawbuf, int bits, int endian){
    int acc = 0;
    uint32_t ins;

    if(!rawbuf) return 1;

    ins = rawbuf[0];

    if(!endian){ // Little Endian
        if(bits == 64){
            acc |= (ins == 0xd65f03c0);  // ret

            acc |= BITS(ins, 31, 25) == 107 && // blr
                    BITS(ins, 24, 23) == 0 &&
                    BITS(ins, 22, 21) == 1 &&
                    BITS(ins, 15, 10) == 0 &&
                    BITS(ins, 4, 0) == 0;

            acc |= BITS(ins, 31, 25) == 107 && // br
                    BITS(ins, 24, 23) == 0 &&
                    BITS(ins, 22, 21) == 0 &&
                    BITS(ins, 15, 10) == 0 &&
                    BITS(ins, 4, 0) == 0;
        }else{
            acc |= BITS(ins, 27, 22) == 34 && // 100010
                    BITS(ins, 20, 20) == 1 && // LDM/LDMIA/LDMFD
                    BITS(ins, 15, 15) == 1;   // make sure r15(pc) is updated

            acc |= BITS(ins, 27, 22) == 32 && // 100000
                    BITS(ins, 20, 20) == 1 && // LDMDA/LDMFA
                    BITS(ins, 15, 15) == 1;   // make sure r15(pc) is updated

            acc |= BITS(ins, 27, 22) == 36 && // 100000
                    BITS(ins, 20, 20) == 1 && // LDMDB/LDMEA
                    BITS(ins, 15, 15) == 1;   // make sure r15(pc) is updated

            acc |= BITS(ins, 27, 22) == 38 && // 100000
                    BITS(ins, 20, 20) == 1 && // LDMIB/LDMED
                    BITS(ins, 15, 15) == 1;   // make sure r15(pc) is updated

            acc |= BITS(ins, 27, 16) == 2237 && // 100010111101 POP
                    BITS(ins, 15, 15) == 1;   // make sure r15(pc) is updated

            acc |= BITS(ins, 27, 4) == 1245169; // bx <reg> 1245169

            acc |= BITS(ins, 27, 4) == 1245171; // blx <reg> 1245169

            /*acc = (((ins >> 25) & 7) == 4) */
                /*&& ((ins >> 20) & 1) */
                /*&& (ins & 0x8000); // Load Multiple instructions that manipulate PC*/

            /*acc |= (((ins >> 8) & 0x1ffff) == 0x12fff); // Branch and Exchange instructions*/
            /*acc |= (((ins >> 24) & 0xff) == 0xef); // SVC*/
        }
    }else{ // TODO: Big Endian
        if(bits == 64){
            acc |= (ins == 0xc0035fd6); // ret

            acc |= BITS(ins, 31, 25) == 107 && // blr
                    BITS(ins, 24, 23) == 0 &&
                    BITS(ins, 22, 21) == 1 &&
                    BITS(ins, 15, 10) == 0 &&
                    BITS(ins, 4, 0) == 0;

            acc |= BITS(ins, 31, 25) == 107 && // br
                    BITS(ins, 24, 23) == 0 &&
                    BITS(ins, 22, 21) == 0 &&
                    BITS(ins, 15, 10) == 0 &&
                    BITS(ins, 4, 0) == 0;
        }else{
            acc = (((ins >> 25) & 7) == 4) 
                && ((ins >> 20) & 1) 
                && (ins & 0x8000); // Load Multiple instructions that manipulate PC

            acc |= (((ins >> 8) & 0x1ffff) == 0x12fff); // Branch and Exchange instructions
            acc |= (((ins >> 24) & 0xff) == 0xef); // SVC
        }
    }
    return acc;
}

/*
// unint32_t *, int, endian -> int
// Is the buffer pointingto a 32-bit Thumb gadget end sequence
// TODO: Implement this
int is_thumb32_end(uint32_t * rawbuf, int bits, int endian){
    int acc = 0;
    uint32_t ins;

    if(!rawbuf) return 1;

    ins = rawbuf[0];
    acc = (((ins >> 8 ) & 255) == 189); // Load Multiple instructions that manipulate PC
    acc |= (((ins >> 8 ) & 255) == 71); // Branch and Exchange instructions
    //acc |= (((ins >> 8) & 255) == 142); // Branch and Exchange instructions
    //acc |= (((ins >> 24) & 255) == 239); // SVC
    return acc;
}
*/

// unint16_t *, int, endian -> int
// Is the buffer pointingto a 16-bit Thumb gadget end sequence
int is_thumb16_end(uint16_t * rawbuf, int bits, int endian){
    int acc = 0;
    uint16_t ins;

    if(!rawbuf) return 1;

    ins = rawbuf[0];
    acc = (((ins >> 8 ) & 0xff) == 0xbd); // Load Multiple instructions that manipulate PC
    acc |= (((ins >> 8 ) & 0xff) == 0x47); // Branch and Exchange instructions
    acc |= (((ins >> 24) & 0xff) == 0xef); // SVC
    return acc;
}


// thumb_node_t *, char *, char *, size_t, size_t, size_t, int, size_t, int
// Generate all the gadgets connected to the Thumb node
void get_children_thumb(thumb_node_t * currnode, char * begptr, char * rawbuf, unsigned long long lowervma, size_t bufsize, int bits, size_t depth, int endian){
    insn_t * it = NULL, * curr = NULL;
    unsigned int rvma = 0;
    char * nrawbuf = NULL;
    it = currnode->insn;
    thumb_node_t * leftn = NULL;
    thumb_node_t * rightn = NULL;

    if(depth == 0) return;

    nrawbuf = rawbuf - 2;
    rvma = it->vma - 2;
    if(nrawbuf < begptr) return;
    if(rvma < lowervma) return;
    if(is_thumb16_end((uint16_t *)nrawbuf, bits, endian)) return;

    curr = disassemble_one(rvma, nrawbuf, bufsize + 2, ARCH_arm, 16, 0);
    if(is_valid_instr(curr, ARCH_arm) && (curr->instr_size == 2) && !is_branch(curr, ARCH_arm)){
        leftn = malloc(sizeof(thumb_node_t));
        if(!leftn){
            perror("malloc");
            exit(-1);
        }
        memset(leftn, 0, sizeof(thumb_node_t));
        leftn->insn = curr;
        currnode->left = leftn;
        get_children_thumb(leftn, begptr, nrawbuf, lowervma, bufsize + 2, bits, depth - 1, endian);
    }

    nrawbuf = rawbuf - 4;
    rvma = it->vma - 4;
    if(nrawbuf < begptr) return;
    if(rvma < lowervma) return;
    //if(is_thumb32_end((uint32_t *)nrawbuf, bits, endian)) return; // TODO: implement this

    curr = disassemble_one(rvma, nrawbuf, bufsize + 4, ARCH_arm, 16, 0);
    if(is_valid_instr(curr, ARCH_arm) && (curr->instr_size == 4) && !is_branch(curr, ARCH_arm)){
        rightn = malloc(sizeof(thumb_node_t));
        if(!rightn){
            perror("malloc");
            exit(-1);
        }
        memset(rightn, 0, sizeof(thumb_node_t));
        rightn->insn = curr;
        currnode->right = rightn;
        get_children_thumb(rightn, begptr, nrawbuf, lowervma, bufsize + 4, bits, depth - 1, endian);
    }
}

// unsigned int, char *, size_t, int, int, size_t
// Generate all the ARM gadgets
gadget_list * generate_arm(unsigned long long vma, char * rawbuf, size_t size, int bits, int endian, size_t depth, char **re){
    insn_t * it;
    unsigned int i = 0, j = 0;
    uint32_t * armbuf = (uint32_t *) rawbuf;
    char * arm64buf = rawbuf;
    uint16_t * thmbuf = (uint16_t *) rawbuf;
    size_t nsize_arm = size / 4;
    size_t nsize_thm = size / 2;
    size_t nsize_arm64 = size;
    thumb_node_t * troot = NULL;

    // From the ARM 32 bit or 64 bit endings
    if(bits == 64){
        for(i = 0; i < nsize_arm64; i++){
            if(is_arm_end((uint32_t *)&arm64buf[i], bits, endian)){
                insn_list * gadget = NULL;
                it = disassemble_one(vma + i, (char *)&arm64buf[i], ARM_INSTR_SIZE, ARCH_arm, bits, endian);
                if(!is_valid_instr(it, ARCH_arm)) continue;
                prepend_instr(it, &gadget);
                for(j = 1; j < depth; j++){
                    char * iptr = (char *)&arm64buf[i] - (j * 4);
                    if(iptr < arm64buf) break;
                    unsigned int nvma = (vma + i * 4) - (j * 4);
                    if(nvma < vma) break;
                    it = disassemble_one(nvma, iptr, ARM_INSTR_SIZE, ARCH_arm, bits, endian);
                    if(!is_valid_instr(it, ARCH_arm) 
                            || is_arm_end((uint32_t *)iptr, bits, endian) 
                            || is_branch(it, ARCH_arm)) break;
                    prepend_instr(it, &gadget);
                }
                print_gadgets_list(&gadget, re);
                free_all_instrs(&gadget);
            }
        }
    }else{
        for(i = 0; i < nsize_arm; i++){
            if(is_arm_end(&armbuf[i], bits, endian)){
                insn_list * gadget = NULL;
                it = disassemble_one(vma + i * 4, (char *)&armbuf[i], ARM_INSTR_SIZE, ARCH_arm, bits, endian);
                if(!is_valid_instr(it, ARCH_arm)) continue;
                prepend_instr(it, &gadget);
                for(j = 1; j < depth; j++){
                    char * iptr = (char *)&armbuf[i] - (j * 4);
                    unsigned int nvma = (vma + i * 4) - (j * 4);
                    if(nvma < vma) break;
                    it = disassemble_one(nvma, iptr, ARM_INSTR_SIZE, ARCH_arm, bits, endian);
                    if(!is_valid_instr(it, ARCH_arm) 
                            || is_arm_end((uint32_t *)iptr, bits, endian) 
                            || is_branch(it, ARCH_arm)) break;
                    prepend_instr(it, &gadget);
                }
                print_gadgets_list(&gadget, re);
                free_all_instrs(&gadget);
            }
        }
    }

    // From the Thumb 16 bit endings
    if(bits != 64){
        for(i = 0; i < nsize_thm; i++){
            if(is_thumb16_end(&thmbuf[i], bits, endian)){
                troot = malloc(sizeof(thumb_node_t));
                if(!troot){
                    perror("malloc");
                    exit(-1);
                }
                memset(troot, 0, sizeof(thumb_node_t));

                it = disassemble_one(vma + i * 2, rawbuf + i * 2, nsize_thm - i * 2, ARCH_arm, 16, endian);
                if(!is_valid_instr(it, ARCH_arm)) continue;
                troot->insn = it;
                get_children_thumb(troot, rawbuf, rawbuf + i * 2, vma, nsize_thm - i * 2, bits, depth, endian);

                print_gadgets_bt(troot, depth, re);
                //print_gadgets_trie(retrootn, depth);
            }
        } 
    }
 
    /* TODO: Implement this
    // From the Thumb 32 bit endings
    for(i = 0; i < nsize_arm; i++){
        if(is_thumb32_end(&armbuf[i], bits, endian)){
            troot = malloc(sizeof(thumb_node_t));
            if(!troot){
                perror("malloc");
                exit(-1);
            }
            memset(troot, 0, sizeof(thumb_node_t));

            it = disassemble_one(vma + i * 4, rawbuf + i * 4, nsize_arm - i * 4, ARCH_arm, 16, endian);
            if(!is_valid_instr(it, ARCH_arm)) continue;
            troot->insn = it;
            get_children_thumb(troot, rawbuf, rawbuf + i * 4, vma, nsize_arm - i * 4, bits, depth, endian);

            print_gadgets_bt(troot, depth);
            //print_gadgets_trie(retrootn, depth);
        }
    }*/

    return NULL;
}
