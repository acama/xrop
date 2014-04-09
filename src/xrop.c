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
#include <stdio.h>
#include <string.h>
#include <stdint.h>

// insn_t, int
// Check if the given instruction is a valid instruction
// and/or was decoded sucessfully
int is_valid_instr(insn_t * i, int arch){
    char c;

    if(!i){
        return 0;
    }
    c = i->decoded_instrs[0];
    
    if(arch == ARCH_x86){
        return (c != '(') && (c != '.') 
                && !strstr(i->decoded_instrs, "(bad)") 
                && !strstr(i->decoded_instrs, "<intern");
    }else if(arch == ARCH_arm){ 
        return (c != '\t') && (c != '.') && !strstr(i->decoded_instrs, "illegal");
        //return !strstr(i->decoded_instrs, "UNDEFINED") && (c != '.');
    }else if(arch == ARCH_mips){
        return (c != '0') && (c != '.');
    }else if(arch == ARCH_powerpc){
        return (c != '.');
    }

    return 0;
}

// insn_t *
// Is the instruction an unconditional branch
int is_branch(insn_t * i, int arch){

    if(arch == ARCH_arm){
        if(strstr(i->decoded_instrs, "b\t"))
            return 1;

        if(strstr(i->decoded_instrs, "b."))
            return 1;

        if(strstr(i->decoded_instrs, "bl"))
            return 1;

        if(strstr(i->decoded_instrs, "bx"))
            return 1;

        if(strstr(i->decoded_instrs, "blx"))
            return 1;
    }

    if(arch == ARCH_x86){
        if(strstr(i->decoded_instrs, "jmp"))
            return 1;
    }

    return 0;
}

// char *, int
// Check if the given buffer is pointing to gadget-end sequence
int is_x86_end(char * rawbuf, int bits){
    int acc;

    if(!rawbuf)
        return 0;

    acc = ((unsigned short *)rawbuf)[0] == (unsigned short)0x80cd || rawbuf[0] == (char) 0xc3;
    
    if(bits == 64) 
        acc |= ((unsigned short *) rawbuf)[0] == 0x050f;

    return acc;
}


// x86_node_t *, char *, char *, size_t, size_t, size_t, int, size_t
// Generate all the gadgets connected to the x86 node
void get_children_x86(x86_node_t * currnode, char * begptr, char * rawbuf, size_t lowervma, size_t bufsize, int bits, size_t depth){
    int i = 0;
    insn_t * it = NULL, * curr = NULL;
    unsigned int rvma = 0;
    it = currnode->insn;

    for(i = 1; i < (X86MAX_INSTR_SIZE) && depth > 0; i++){
        char * nrawbuf = rawbuf - i;
        rvma = it->vma - i;
        if(nrawbuf < begptr) break;
        if(rvma < lowervma) break;
        if(is_x86_end(nrawbuf, bits)) break;
        
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

// insn_t * -> void
// Print a gadget in a formatted way
void print_gadget(insn_t * ins, int type, int isthumb){
    char * dec = NULL, * ptr = NULL;
    if(!ins){
        return;
    }
 
    dec = ins->decoded_instrs;

    if(type == END_OUTPUT || type == SPECIAL_OUTPUT){
        if(isthumb)
            printf("\e[34;1m> 1 + 0x%-18x\e[m", (unsigned int)ins->vma);
        else 
            printf("\e[34;1m> 0x%-22x\e[m", (unsigned int)ins->vma);
    }else{
        if(isthumb)
            printf("\e[34m1 + 0x%-20x\e[m", (unsigned int)ins->vma);
        else 
            printf("\e[34m0x%-24x\e[m", (unsigned int)ins->vma);
    }

    // remove uninteresting comments inserted by disassembler
    if((ptr = strstr(dec, "; <U"))){  // "; <UNPREDICTABLE>"
        ptr[0] = '\0'; 
    }
    if((ptr = strstr(dec, "; u"))){   // "; unpredictable branch in IT block"
        ptr[0] = '\0'; 
    }
    
    if(type == BEG_OUTPUT || type == SPECIAL_OUTPUT){
        printf("\e[31m%s\n\e[m", ins->decoded_instrs);
    }else{
        printf("%s\n", ins->decoded_instrs);
    }

}

// insn_t *, int, int
// Print the path with the given output option
void print_path(insn_t * path[], int pathlen, int output){
    int i = 0;

    if(pathlen == 0){
        return;
    }

    for(i = pathlen; i >= 0; i--){
        if(i == pathlen) print_gadget(path[i], END_OUTPUT, output);
        else if(i == 0) print_gadget(path[i], BEG_OUTPUT, output);
        else print_gadget(path[i], MID_OUTPUT, output);
    }

    printf("_______________________________________________________________\n\n");
}

// x86_node_t *, insn_t *, size_t, int
// Recursively print the gadgets in the x86 trie
void r_print_gadgets_trie(x86_node_t * n, insn_t * path[], size_t depth, int pathlen){
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
            r_print_gadgets_trie(tmp, path, depth - 1, pathlen + 1);
        }
    }

    if(acc){
        print_path(path, pathlen, NORM_INSTR);
    }

}

// x86_node_t *, size_t
// Print the gadgets in the x86 trie
void print_gadgets_trie(x86_node_t * n, size_t depth){
    insn_t * path[MAX_GADGET_LEN] = {0};
    r_print_gadgets_trie(n, path, depth, 0);
}

// thumb_node_t *, insn_t *, size_t, int
// Recursively print the gadgets in the Thumb binary tree
void r_print_gadgets_bt(thumb_node_t * n, insn_t * path[], size_t depth, int pathlen){
    thumb_node_t * tmp = NULL;   

    if(n == NULL) return;
    path[pathlen] = n->insn;
 
    if((int)depth < 0){
        return;
    }

    if((n->left == NULL) && (n->right == NULL)){
        print_path(path, pathlen, THUMB_INSTR);
    }

    tmp = n->left;
    if(tmp){
        r_print_gadgets_bt(tmp, path, depth - 1, pathlen + 1);
    }
    
    tmp = n->right;
    if(tmp){
        r_print_gadgets_bt(tmp, path, depth - 1, pathlen + 1);
    }

}

// thumb_node_t *, size_t
// Print the gadgets in the Thumb binary tree
void print_gadgets_bt(thumb_node_t * n, size_t depth){
    insn_t * path[MAX_GADGET_LEN] = {0};
    r_print_gadgets_bt(n, path, depth, 0);
}

// unsigned int, char *, size_t, int, size_t
// Generate the x86 gadgets in the given buffer
gadget_list * generate_x86(unsigned int vma, char * rawbuf, size_t size, int bits, size_t depth){
    insn_t * it = NULL;
    int i = 0;
    unsigned int rvma = 0;
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

            print_gadgets_trie(retrootn, depth);
        }

    }

    return NULL;
}

// insn_list ** -> void
// Print all the instructions in the list
void print_gadgets_list(insn_list **ilist){
    insn_list * l = *ilist;

    if(l){
        if(!l->next) print_gadget(l->instr, SPECIAL_OUTPUT, NORM_INSTR);
        else print_gadget(l->instr, END_OUTPUT, NORM_INSTR);
    }

    l = l->next;
    while(l){
        if(!l->next) print_gadget(l->instr, BEG_OUTPUT, NORM_INSTR);
        else print_gadget(l->instr, MID_OUTPUT, NORM_INSTR);
        l = l->next;
    }
    
    printf("_______________________________________________________________\n\n");
}

// unint32_t *, int, int -> int
// Is the buffer pointing to a ARM gadget end sequence
int is_arm_end(uint32_t * rawbuf, int bits, int endian){
    int acc = 0;
    uint32_t ins;

    if(!rawbuf) return 1;

    ins = rawbuf[0];

    acc = (((ins >> 25) & 7) == 4) 
        && ((ins >> 20) & 1) 
        && (ins & 0x8000); // Load Multiple instructions that manipulate PC

    acc |= (((ins >> 8) & 0x1ffff) == 0x12fff); // Branch and Exchange instructions
    acc |= (((ins >> 24) & 0xff) == 0xef); // SVC

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
    acc |= (((ins >> 8) & 0xff) == 0x8e); // Pop
    acc |= (((ins >> 24) & 0xff) == 0xef); // SVC
    return acc;
}


// thumb_node_t *, char *, char *, size_t, size_t, size_t, int, size_t, int
// Generate all the gadgets connected to the Thumb node
void get_children_thumb(thumb_node_t * currnode, char * begptr, char * rawbuf, size_t lowervma, size_t bufsize, int bits, size_t depth, int endian){
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
gadget_list * generate_arm(unsigned int vma, char * rawbuf, size_t size, int bits, int endian, size_t depth){
    insn_t * it;
    unsigned int i = 0, j = 0;
    uint32_t * armbuf = (uint32_t *) rawbuf;
    uint16_t * thmbuf = (uint16_t *) rawbuf;
    size_t nsize_arm = size / 4;
    size_t nsize_thm = size / 2;
    thumb_node_t * troot = NULL;

    // From the ARM 32 bit endings
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
            print_gadgets_list(&gadget);
            free_all_instrs(&gadget);
        }
    }

    // From the Thumb 16 bit endings
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

            print_gadgets_bt(troot, depth);
            //print_gadgets_trie(retrootn, depth);
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

gadget_list * generate_powerpc(unsigned int vma, char * rawbuf, size_t size, int bits, int endian, size_t depth){
    return NULL;
}

gadget_list * generate_mips(unsigned int vma, char * rawbuf, size_t size, int bits, int endian, size_t depth){
    return NULL;
}

// unsigned int, char *, size_t, int, int, int, size_t
// Search for gadgets in given buffer
gadget_list * gadget_search(unsigned int vma, char * rawbuf, size_t size, int arch, int bits, int endian, size_t depth){
    gadget_list * l = NULL;

    if(arch == ARCH_x86){
        l = generate_x86(vma, rawbuf, size, bits, depth); 
    }else if(arch == ARCH_arm){
        l = generate_arm(vma, rawbuf, size, bits, endian, depth);
    }else if(arch == ARCH_powerpc){ 
        l = generate_arm(vma, rawbuf, size, bits, endian, depth);
    }else if(arch == ARCH_mips){ 
        l = generate_mips(vma, rawbuf, size, bits, endian, depth);
    }

    return l;
}

