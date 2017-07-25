/*
    main.c -- Main file
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

#define PACKAGE 1
#define PACKAGE_VERSION 1.1
#include "bfd.h"
#include "dis-asm.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <malloc.h>
#include "elf/external.h"
#include "elf/internal.h"
#include "elf-bfd.h"

#include "libxdisasm/include/xdisasm.h"
#include "../include/xrop.h"
#include "../include/color_print.h"

#define VERSION "1.1"
#define XNAME "xrop"

#define elf_tdata(bfd)		((bfd) -> tdata.elf_obj_data)

// Print version
void print_version(){
    printf("%s %s \n", XNAME, VERSION);
    exit(0);
}
// Print usage
void print_usage(){
    printf("Usage: xrop [-r arch] [-b bits] [-e bytes] [-l endian] [-a relocaddr] [-s regex] [-v] [-h] inputfile\n");
    printf("\t -b (16 | 32 | 64) sets the processor mode\n");
    printf("\t -r (arm | mips | powerpc | x86) raw binary file of given architecture\n");
    printf("\t -v displays the version number\n");
    printf("\t -l (b | e) big or little endian\n");
    printf("\t -e skips <bytes> of header\n");
    printf("\t -a rellocate at given address\n");
    printf("\t -n disable colors in the output\n");
    printf("\t -s filter gadgets with <regex>\n");
    printf("\t -h prints this menu\n");
    exit(0);
}

// bfd *, asection *, int, unsigned long, bits, endian, depth -> void
// Get the raw bytes of the section and pass it to the gadget search function
void handle_section(bfd * bfdh, asection * section, config_t * cfg){
    bfd_size_type size;
    char * rawbytes;

    size = bfd_section_size(bfdh, section);
    rawbytes = (char *) malloc(size);

    if(!rawbytes){
        fprintf(stderr, "%s: Couldn't allocate memory for section data\n", XNAME);
        exit(-1);
    }

    if(!bfd_get_section_contents(bfdh, section, rawbytes, 0, size)){
        fprintf(stderr, "%s: Couldn't read section data\n", XNAME);
        exit(-1);
    }
   
    cfg->vma = bfd_section_vma(bfdh, section);
    gadget_search(rawbytes, size, cfg);
    free(rawbytes);
}

int in_exec_range(seginfo_t *info, size_t infosize, unsigned long long start, unsigned long long end){
    unsigned int i;

    for(i = 0; i < infosize; i++){
        if(info[i].isset){
            if(start >= info[i].start_addr && end < info[i].end_addr){
                return 1;    
            }
        }
    }

    return 0;
}

// char *, size_t -> int
// Open the given executable file, handle each executable section
int handle_execable(char * infile, size_t depth, char ** re){
    bfd * bfdh;
    asection * section;
    enum bfd_architecture barch;
    unsigned long mach;
    int arch, bits = 0;
    int endian = 0;
    size_t sdepth = depth;
    config_t cfg = {0};
    Elf_Internal_Phdr *p;
    seginfo_t * exec_segments = NULL; // list of executable segments only used with ELF
    size_t num_segments = 0;

    bfdh = bfd_openr(infile, NULL);
    if(!bfdh){
        fprintf(stderr, "%s: Couldn't open file %s\n", XNAME, infile);
        exit(-1);
    }

    if (!bfd_check_format(bfdh, bfd_object)) {
        if (bfd_get_error() != bfd_error_file_ambiguously_recognized) {
            fprintf(stderr, "%s: Unknown file format\n", XNAME);
            exit(-1);
        }
    }

    barch = bfd_get_arch(bfdh);
    mach = bfd_get_mach(bfdh);
    
    if(bfd_big_endian(bfdh))
            endian = 1;

    if(barch == bfd_arch_arm){ // ARM
        printf("Searching ROP gadgets for \"%s\" - ",infile);
        green_printf("ARM Executable");
        printf("...\n");
        arch = ARCH_arm;
    }else if(barch == bfd_arch_aarch64){
        printf("Searching ROP gadgets for \"%s\" - ",infile);
        green_printf("ARM64 Executable");
        printf("...\n");
        arch = ARCH_arm;
        bits = 64;
    }else if(!strcmp(bfdh->xvec->name, "pei-arm-little")){ // workaround since binutils not 
                                                           //handling this type of binary properly
        arch = ARCH_arm;
    }else if(barch == bfd_arch_i386){ // x86
        arch = ARCH_x86;
        if(mach == bfd_mach_i386_i8086){
            printf("Searching ROP gadgets for 16-bit is not supported\n");
            exit(-1);
        }else if(mach == bfd_mach_i386_i386){
            printf("Searching ROP gadgets for \"%s\" - ",infile);
            green_printf("x86 Executable");
            printf("...\n");
            bits = 32;
        }else{
            printf("Searching ROP gadgets for \"%s\" - ",infile);
            green_printf("x86_64 Executable");
            printf("...\n");
            bits = 64;
        }
    }else if(barch == bfd_arch_mips){ // MIPS 
        printf("Searching ROP gadgets for \"%s\" - ",infile);
        green_printf("MIPS Executable");
        printf("...\n");
        arch = ARCH_mips;
        sdepth = MIPS_DEFAULT_DEPTH;
    }else if(barch == bfd_arch_powerpc){ // PPC
        printf("Searching ROP gadgets for \"%s\" - ",infile);
        green_printf("PowerPC Executable");
        printf("...\n");
        arch = ARCH_powerpc;
        sdepth = PPC_DEFAULT_DEPTH;
    }else if(barch == bfd_arch_riscv){ // RISCV
        printf("Searching ROP gadgets for \"%s\" - ",infile);
        green_printf("RISCV Executable");
        printf("...\n");
        arch = ARCH_riscv;
        bits = 64; 
        sdepth = RISCV_DEFAULT_DEPTH;
    }else if(barch == bfd_arch_sh){ // SH4
        printf("Searching ROP gadgets for \"%s\" - ",infile);
        green_printf("SH4 Executable");
        printf("...\n");
        arch = ARCH_sh4;
        sdepth = SH4_DEFAULT_DEPTH;
    }else if(barch == bfd_arch_sparc){ // SPARC
        printf("Searching ROP gadgets for \"%s\" - ",infile);
        green_printf("SPARC Executable", infile);
        printf("...\n");
        arch = ARCH_sparc;
        bits = mach; // special meaning for SPARC
        sdepth = SPARC_DEFAULT_DEPTH;
    }else{
        printf("%s: Unsupported architecture %s\n, %d, %d", XNAME, bfdh->xvec->name, barch, (int)mach);
        return -1;
    }

    p = elf_tdata(bfdh)->phdr;
    // if we are an ELF
    if(p != NULL){
        unsigned int i;
        num_segments = elf_elfheader (bfdh)->e_phnum;
        exec_segments = calloc(num_segments, sizeof(seginfo_t));   // list of segments
        for(i = 0; i < num_segments; i++, p++){
            if(p->p_flags & PF_X){
                exec_segments[i].start_addr = p->p_vaddr; 
                exec_segments[i].end_addr = p->p_vaddr + p->p_memsz; 
                exec_segments[i].isset = 1; 
            }
        }
    }

    for(section = bfdh->sections; section; section = section->next){
        flagword flags = bfd_get_section_flags(bfdh, section);
        unsigned long long cur_vma = bfd_section_vma(bfdh, section);
        bfd_size_type cur_size = bfd_section_size(bfdh, section);
        unsigned long long cur_vma_end = cur_vma + cur_size;
        if(p != NULL && num_segments != 0){
            // means this is an ELF so we only care about segments
            if(in_exec_range(exec_segments, num_segments, cur_vma, cur_vma_end)){
                printf("\n");
                green_printf(" -> [ %s ]\n", bfd_section_name(bfdh, section));

                cfg.arch = arch;
                cfg.bits = bits;
                cfg.endian = endian;
                cfg.depth = sdepth;
                cfg.re = re;

                handle_section(bfdh, section, &cfg);
            }
        }else if((flags & SEC_LOAD) && (flags & SEC_CODE)){
            // some other file format
            printf("\n");
            green_printf(" -> [ %s ]\n", bfd_section_name(bfdh, section));

            cfg.arch = arch;
            cfg.bits = bits;
            cfg.endian = endian;
            cfg.depth = sdepth;
            cfg.re = re;

            handle_section(bfdh, section, &cfg);
        }
    }

    free(exec_segments);
    return 0;
}

// char *, size_t, int, int, int, unsigned int, size_t
// Open given file and handle as raw binary
int handle_raw(char * infile, size_t hdrlen, config_t * cfg){
    FILE * fp = NULL;
    size_t datalen = 0;
    char * data = NULL;

    fp = fopen (infile, "rb");

    if (fp){
        fseek (fp, hdrlen, SEEK_END);
        datalen = ftell (fp);       // TODO: maybe check if vma + datalen will overflow address range
        if(datalen < 0){
            perror("ftell");
            exit(-1);
        }
        if(datalen == 0){
            printf("%s: file %s is empty", XNAME, infile);
        }
        fseek (fp, hdrlen, SEEK_SET);
        data = malloc (datalen);
        if (data)
        {
            if(fread (data, 1, datalen, fp) != datalen){
                perror("fread");
                exit(-1);
            }
        }else{
            perror("malloc");
            exit(-1);
        }
        fclose (fp);
    }else{
        perror("fopen");
        exit(-1);
    }

    gadget_search(data, datalen, cfg);
    free(data);
    return 0;
}

int main(int argc, char **argv){
    int opt, endian = 0;
    int fb = 0, fv = 0, fh = 0, bits = 0, arch = 0, fl = 0, fr = 0, fd = 0;
    char * bval = NULL;
    char * dval = NULL;
    char * rval = NULL;
    char * eval = NULL;
    char * aval = NULL;
    char * infile = NULL;
    char ** re = NULL;                  // allow multiple regexes
    size_t re_idx = 0;                  // index of regex
    size_t hdrlen = 0;
    size_t depth = DEFAULT_DEPTH;
    unsigned long long vma = 0;
    char endianchar = 0;
    config_t cfg = {0};


    while((opt = getopt(argc, argv, "b:r:e:a:vhnl:d:s:")) != -1){
        switch(opt){
            case 'b':
                fb = 1;
                bval = optarg;
                break;
            case 'd':
                fd = 1;
                dval = optarg;
                break;
            case 'r':
                fr = 1;
                rval = optarg;
                break;
            case 'e':
                eval = optarg;
                break;
            case 'v':
                fv = 1;
                break;
            case 'h':
                fh = 1;
                break;
            case 'l':
                fl = 1;
                endianchar = optarg[0];
                break;
            case 'a':
                aval = optarg;
                break;
            case 'n':
                xrop_no_color_g=1;
                xdisasm_no_color_g=1;
                break;
            case 's':
                if(!re){
                    re = calloc(MAX_REGEX + 1, sizeof(char *));
                    if(!re){
                        perror("calloc re"); 
                        exit(-1);
                    }
                }
                if(re_idx >= MAX_REGEX){
                    fprintf(stderr, "Too many regex'es specified\n"); 
                    exit(-1);
                }
                re[re_idx++] = optarg;
                break;
            default:
            case '?':
                print_usage();
        }
    }

    if(re){
        re[re_idx] = NULL;
    }

    // version
    if(fv){
        print_version();
    }

    // usage
    if(fh){
        print_usage();
    }

    // filename
    if (!argv[optind]) {
        print_usage();
    }

    infile = argv[optind];

    // load address
    if(aval){
        vma = strtoull(aval, NULL, 0);
        if(vma == LONG_MAX || vma == LONG_MIN || vma == 0){
            perror("strtol");
            exit(-1);
        }
    }

    // bits
    if(fb){
        bits = strtol(bval, NULL, 10);
        if(bits != 16 && bits != 32 && bits != 64){
            print_usage(); 
        }
    }

    // depth of search
    if(fd){
        depth = strtol(dval, NULL, 10);
        if(depth > MAX_DEPTH){
            printf("%s: max depth is %d, using that value\n", XNAME, MAX_DEPTH);
            depth = MAX_DEPTH;
        }
    }

    // endianness
    if(fl){
        if(endianchar == 'b') endian = 1;
        else if(endianchar == 'e') endian = 0;
        else print_usage();
    }

    if(rval){
        if(!strcmp(rval, "arm")){
            arch = ARCH_arm;
        }
        else if(!strcmp(rval, "powerpc")){
            arch = ARCH_powerpc;
        } 
        else if(!strcmp(rval, "x86")){
            arch = ARCH_x86;
        } 
        else if(!strcmp(rval, "mips")){
            arch = ARCH_mips;
        }
        else{
            print_usage();
        }
    }

    if(eval){ 
        hdrlen = strtol(eval, NULL, 10);
        if(hdrlen == LONG_MAX || hdrlen == LONG_MIN || hdrlen == 0){
            perror("strtol");
            exit(-1);
        }
    }

    if(fr){
        cfg.vma = vma;
        cfg.arch = arch;
        cfg.bits = bits;
        cfg.endian = endian;
        cfg.depth = depth;
        cfg.re = re;

        handle_raw(infile, hdrlen, &cfg);
    }else{
        handle_execable(infile, depth, re);
    }

    return 0;
}
