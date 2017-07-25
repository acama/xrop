#ifndef COLOR_PRINT_H
#define COLOR_PRINT_H

extern int xrop_no_color_g;

enum colors
{
    BrightBlack=0,
    Black,  //more like gray
    BrightRed,
    Red,
    BrightGreen,
    Green,
    BrightYellow,
    Yellow,
    BrightBlue,
    Blue,
    BrightMagenta,
    Magenta,
    BrightCyan,
    Cyan,
    BrightWhite,
    White,
    LessBright,
    END_COLORS
};

void __color_printf(enum colors colorcode, const char* format, ...);

#define br_blue_printf(...)     __color_printf(BrightBlue,__VA_ARGS__)
#define blue_printf(...)        __color_printf(Blue,__VA_ARGS__)
#define br_red_printf(...)      __color_printf(BrightRed,__VA_ARGS__)
#define red_printf(...)         __color_printf(Red,__VA_ARGS__)
#define br_green_printf(...)    __color_printf(BrightGreen,__VA_ARGS__)
#define green_printf(...)       __color_printf(Green,__VA_ARGS__)
#define dim_printf(...)         __color_printf(LessBright,__VA_ARGS__)

#endif /* COLOR_PRINT_H */
