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
#include <regex.h>

// char *, char * -> int
// perform regex matching on given string with pattern
int reg_match(char * str, char * re){
    regex_t regex;
    int reti;
    //char msgbuf[100];

    // Compile regular expression
    reti = regcomp(&regex, re, 0);
    if( reti ){ fprintf(stderr, "Could not compile regex\n"); exit(1); }

    // Execute regular expression
    reti = regexec(&regex, str, 0, NULL, 0);

    /*
    if( !reti ){
        puts("Match");
    }
    else if( reti == REG_NOMATCH ){
        puts("No match");
    }
    else{
        regerror(reti, &regex, msgbuf, sizeof(msgbuf));
        fprintf(stderr, "Regex match failed: %s\n", msgbuf);
        exit(1);
    }*/

    // Free compiled regular expression if you want to use the regex_t again
    regfree(&regex);

    return reti;
}


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

    return 0;
}


// insn_t * -> void
// Print a gadget in a formatted way (with colors)
void print_gadget(insn_t * ins, int type, int isthumb){
    char * dec = NULL, * ptr = NULL;
    if(!ins){
        return;
    }
 
    dec = ins->decoded_instrs;

    if(type == END_OUTPUT || type == SPECIAL_OUTPUT){
        if(isthumb)
            printf("\e[34;1m> 1 + %-18p\e[m", (void *)ins->vma);
        else 
            printf("\e[34;1m> %-22p\e[m", (void *)ins->vma);
    }else{
        if(isthumb)
            printf("\e[34m1 + %-20p\e[m", (void *)ins->vma);
        else 
            printf("\e[34m%-24p\e[m", (void *)ins->vma);
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

// insn_t * -> void
// Print a gadget in a formatted way (without colors)
void print_gadget_wc(insn_t * ins, int type, int isthumb){
    char * dec = NULL, * ptr = NULL;
    if(!ins){
        return;
    }
 
    dec = ins->decoded_instrs;

    if(type == END_OUTPUT || type == SPECIAL_OUTPUT){
        if(isthumb)
            printf("> 1 + %-18p", (void *)ins->vma);
        else 
            printf("> %-22p", (void *)ins->vma);
    }else{
        if(isthumb)
            printf("1 + %-20p", (void *)ins->vma);
        else 
            printf("%-24p", (void *)ins->vma);
    }

    // remove uninteresting comments inserted by disassembler
    if((ptr = strstr(dec, "; <U"))){  // "; <UNPREDICTABLE>"
        ptr[0] = '\0'; 
    }
    if((ptr = strstr(dec, "; u"))){   // "; unpredictable branch in IT block"
        ptr[0] = '\0'; 
    }
    
    if(type == BEG_OUTPUT || type == SPECIAL_OUTPUT){
        printf("%s\n", ins->decoded_instrs);
    }else{
        printf("%s\n", ins->decoded_instrs);
    }

}

// insn_list ** -> void
// Print all the instructions in the list with the given regex
void print_gadgets_list(insn_list **ilist, char * re){
    insn_list * l = *ilist;
    int acc = 0;

    if(re){
        while(l){
           acc |= !reg_match(l->instr->decoded_instrs, re); 
           l = l->next;
        }
        if(!acc) return;
    }

    l = *ilist;

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
void print_path(insn_t * path[], int pathlen, int output, char * re){
    int i = 0;
    int acc = 0;


    if(pathlen == 0){
        return;
    }

    if(re){
        for(i = pathlen; i >= 0; i--){
            acc |= !reg_match(path[i]->decoded_instrs, re);
        }
        if(!acc) return;
    }

    for(i = pathlen; i >= 0; i--){
        if(i == pathlen) print_gadget(path[i], END_OUTPUT, output);
        else if(i == 0) print_gadget(path[i], BEG_OUTPUT, output);
        else print_gadget(path[i], MID_OUTPUT, output);
    }

    printf("_______________________________________________________________\n\n");
}
