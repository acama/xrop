/*
    common.c -- Common functions
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



// insn_t, int
// Check if the given instruction is a valid instruction
// and/or was decoded sucessfully
int is_valid_instr(insn_t * i, int arch){
    char c;
/*
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
    }else if(arch == ARCH_mips){
        return (c != '0') && (c != '.');
    }else if(arch == ARCH_powerpc){
        return (c != '.');
    }
*/
    return 0;
}

// insn_t *
// Is the instruction an unconditional branch
int is_branch(insn_t * i, int arch){
/*
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

    if(arch == ARCH_mips){
        if(strstr(i->decoded_instrs, "b\t"))
            return 1;

        if(strstr(i->decoded_instrs, "j\t"))
            return 1;
        
        if(strstr(i->decoded_instrs, "jr"))
            return 1;

        if(strstr(i->decoded_instrs, "jal"))
            return 1;

        if(strstr(i->decoded_instrs, "jalr"))
            return 1;
    }
    
    if(arch == ARCH_powerpc){
        if(strstr(i->decoded_instrs, "b\t"))
            return 1;

        if(strstr(i->decoded_instrs, "bl\t"))
            return 1;
    }

    if(arch == ARCH_x86){
        if(strstr(i->decoded_instrs, "jmp"))
            return 1;
    }

*/
    return 0;
}


// insn_t * -> void
// Print a gadget in a formatted way
void print_gadget(cs_insn * ins, int type, int isthumb){
    char * dec = NULL, * ptr = NULL;
    if(!ins){
        return;
    }
 
    if(type == END_OUTPUT || type == SPECIAL_OUTPUT){
        if(isthumb)
            printf("\e[34;1m> 1 + %-18p\e[m", (void *)ins[0].address);
        else 
            printf("\e[34;1m> %-22p\e[m", (void *)ins[0].address);
    }else{
        if(isthumb)
            printf("\e[34m1 + %-20p\e[m", (void *)ins[0].address);
        else 
            printf("\e[34m%-24p\e[m", (void *)ins[0].address);
    }

    
    if(type == BEG_OUTPUT || type == SPECIAL_OUTPUT){
        printf("\e[31m%s\t%s\n\e[m", ins[0].mnemonic, ins[0].op_str);
    }else{
        printf("%s\t%s\n", ins[0].mnemonic, ins[0].op_str);
    }

}
/*
void print_gadget(cs_insn * it, int type, int isthumb){
    printf("0x%p:\t%s\t\t%s\n", it[0].address, it[0].mnemonic, it[0].op_str);
}*/
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

// insn_t *, int, int
// Print the path with the given output option
void print_path(cs_insn * path[], int pathlen, int output){
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
// insn_t -> void
// Free the memory
void free_instr(insn_t *i){
    
    if(!i){
        return;
    }
    
    free(i->decoded_instrs);
    free(i->opcodes);
    free(i);
}

// insn_list ** -> void
// Free the memory
// Dirty
void free_all_instrs(insn_list **ilist){
    insn_list * l, * f;

    if(!ilist){
        return;
    }
    l = *ilist;

    /* free the insn_t's */
    while(l != NULL){
        free_instr(l->instr);
        f = l;
        l = l->next;
        free(f);
    }
}

// insn_t * -> void
// Print instruction in a formatted way
void print_instr(insn_t * ins){
    size_t i, l;
    char * tmpbuf, * ptr;

    if(!ins)
        return;

    printf("%016llX  ", ins->vma);
    l = ins->instr_size;
   
    tmpbuf = (char *) malloc((l * 2) + 1);

    if(!tmpbuf){
        perror("malloc");
        return;
    }

    ptr = tmpbuf;
    for(i = 0; i < l; i++){
        sprintf(ptr, "%02X", (unsigned char)(ins->opcodes[i]));
        ptr += 2;
    }

    if(l < 15)
        printf("%-18s", tmpbuf);
    else
        printf("%-36s", tmpbuf);
    printf("%s\n", ins->decoded_instrs);
    free(tmpbuf);
}

/*
// insn_list ** -> void
// Print all the instructions in a formatted way
void print_all_instrs(insn_list **ilist){
    insn_list * l = *ilist;

    while(l != NULL){
        print_instr(l->instr);
        l = l->next;
    }
}
*/

// insn_list ** -> size_t
// Count the number of instructions in the list
size_t instr_num(insn_list **ilist){
    insn_list * l;
    size_t len = 0;

    if(!ilist)
        return 0;

    l = *ilist;

    while(l != NULL){
        len++;
        l = l->next;
    }

    return len;
}

// insn_t *, insn_list ** -> void
// Initialize list
void init_list(insn_t *i, insn_list **ilist){
    insn_list * l = (insn_list *) malloc(sizeof(insn_list));

    if(!l){
        perror("malloc");
        return;
    }

    l->instr = i;
    l->next = NULL;
    *ilist = l;
}

// insn_t *, insn_list ** -> void
// Prepend instruction to list
void prepend_instr(insn_t * i, insn_list **ilist){
    insn_list * tmp, *c;

    if(!ilist)
        return;

    c = *ilist;

    if(!c){
        init_list(i, ilist);
        return;
    }


    tmp = (insn_list *) malloc(sizeof(insn_list));
    tmp->instr = i;
    tmp->next = *ilist;

    *ilist = tmp; 
}

// insn_t *, insn_list ** -> void
// Append instruction to list
void append_instr(insn_t * i, insn_list **ilist){
    insn_list * tmp, *c;

    if(!ilist)
        return;

    c = *ilist; 
    
    if(!c){
        init_list(i, ilist);
        return;
    }

    while(c->next != NULL){
        c = c->next;
    }

    tmp = (insn_list *) malloc(sizeof(insn_list));
    tmp->instr = i;
    tmp->next = NULL;

    c->next = tmp; 
}
