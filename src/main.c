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
#define PACKAGE_VERSION 1
#include <bfd.h>
#include <dis-asm.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <malloc.h>
#include "libxdisasm/include/xdisasm.h"
#include "../include/xrop.h"

#define VERSION "1.0"
#define XNAME "xrop"

// Print version
void print_version(){
    printf("%s %s \n", XNAME, VERSION);
    exit(0);
}

// Print usage
void print_usage(){
    printf("Usage: xrop [-r arch] [-b bits] [-e bytes] [-l endian] [-a relocaddr] [-v] [-h] inputfile\n");
    printf("\t -b (16 | 32 | 64) sets the processor mode\n");
    printf("\t -r (arm | mips | powerpc | x86) raw binary file of given architecture\n");
    printf("\t -v displays the version number\n");
    printf("\t -l (b | e) big or little endian\n");
    printf("\t -e skips <bytes> of header\n");
    printf("\t -a rellocate at given address\n");
    printf("\t -h prints this menu\n");
    exit(0);
}

// bfd *, asection *, int, unsigned long, bits, endian, depth -> void
// Get the raw bytes of the section and pass it to the gadget search function
void handle_section(bfd * bfdh, asection * section, int arch, unsigned long mach, int bits, int endian, size_t depth){
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
    
    gadget_search(bfd_section_vma(bfdh, section), rawbytes, size, arch, bits, endian, depth);
    free(rawbytes);
}

// char *, size_t -> int
// Open the given executable file, handle each executable section
int handle_execable(char * infile, size_t depth){
    bfd * bfdh;
    asection * section;
    enum bfd_architecture barch;
    unsigned long mach;
    int arch, bits;
    int endian = 0;
    size_t sdepth = depth;

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
        printf("Searching ROP gadgets for \"%s\" - \e[32mARM Executable\e[m...\n", infile);
        arch = ARCH_arm;
    }else if(barch == bfd_arch_i386){ // x86
        arch = ARCH_x86;
        if(mach == bfd_mach_i386_i8086){
            printf("Searching ROP gadgets for 16-bit is not supported\n");
            exit(-1);
        }else if(mach == bfd_mach_i386_i386){
            printf("Searching ROP gadgets for \"%s\" - \e[32mx86 Executable\e[m...\n", infile);
            bits = 32;
        }else{
            printf("Searching ROP gadgets for \"%s\" - \e[32mx86_64 Executable\e[m...\n", infile);
            bits = 64;
        }
    }else if(barch == bfd_arch_mips){ // MIPS 
        printf("Searching ROP gadgets for \"%s\" - \e[32mMIPS Executable\e[m...\n", infile);
        arch = ARCH_mips;
        sdepth = MIPS_DEFAULT_DEPTH;
    }else if(barch == bfd_arch_powerpc){ // PPC
        printf("Searching ROP gadgets for \"%s\" - \e[32mPowerPC Executable\e[m...\n", infile);
        arch = ARCH_powerpc;
        sdepth = PPC_DEFAULT_DEPTH;
    }else{
        printf("%s: Unsupported architecutre\n", XNAME);
        return -1;
    }

    for(section = bfdh->sections; section; section = section->next){
        flagword flags = bfd_get_section_flags(bfdh, section);
        if((flags & SEC_LOAD) && (flags & SEC_CODE)){
            printf("\n");
            printf("\e[32m[ %s ]\e[m\n", bfd_section_name(bfdh, section));
            handle_section(bfdh, section, arch, mach, bits, endian, sdepth);
        }
    }

    return 0;
}

// char *, size_t, int, int, int, unsigned int, size_t
// Open given file and handle as raw binary
int handle_raw(char * infile, size_t hdrlen, int arch, int bits, int endian, unsigned long long vma, size_t depth){
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
            fread (data, 1, datalen, fp);
        }else{
            perror("malloc");
            exit(-1);
        }
        fclose (fp);
    }else{
        perror("fopen");
        exit(-1);
    }

    gadget_search(vma, data, datalen, arch, bits, endian, depth);
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
    size_t hdrlen = 0;
    size_t depth = DEFAULT_DEPTH;
    unsigned int vma = 0;
    char endianchar = 0;

    while((opt = getopt(argc, argv, "b:r:e:a:vhl:d:")) != -1){
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
            default:
            case '?':
                print_usage();
        }
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
        vma = strtol(aval, NULL, 0);
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
        handle_raw(infile, hdrlen, arch, bits, endian, vma, depth);
    }else{
        handle_execable(infile, depth);
    }

    return 0;
}
