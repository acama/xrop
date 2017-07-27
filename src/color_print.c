#include "../include/print_color.h"
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

int xrop_no_color_g=0;

/* Color table
 *                     Black	Red     Green	Yellow	Blue	Magenta	Cyan	White
 * Foreground Code	    30	    31	    32	    33	    34	    35	    36	    37
 * Background Code	    40	    41	    42	    43	    44	    45      46	    47
 */

static char *foreground_colors[END_COLORS]={
    "\e[30;1m", //Bright black/gray
    "\e[30m",   //Black
    "\e[31;1m", //Bright Read
    "\e[31m",   //Red
    "\e[32;1m", //Bright Green
    "\e[32m",   //Green
    "\e[33;1m", //Bright Yellow
    "\e[33m",   //Yellow
    "\e[34;1m", //Bright Blue
    "\e[34m",   //Blue
    "\e[35;1m", //Bright Magenta
    "\e[35m",   //Magenta
    "\e[36;1m", //Bright Cyan
    "\e[36m",   //Cyan
    "\e[37;1m", //Bright White
    "\e[37m",   //White
    "\e[2m"     //Dim
};


void __color_printf(enum colors colorcode, const char* format, ...)
{
    int print_colors=(!xrop_no_color_g && (colorcode < sizeof(foreground_colors)/sizeof(char *)));
    if(print_colors)
    {
        printf("%s",foreground_colors[colorcode]);
    }
    va_list argptr;
    va_start(argptr, format);
    vfprintf(stdout, format, argptr);
    va_end(argptr);
    if(print_colors)
    {
        printf("\e[m");
    }
}
