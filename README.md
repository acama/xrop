xrop
=======

xrop is a simple tool to generate ROP gadgets. It supports PE, ELF, Mach-O and perhaps other executable formats. It uses the [libxdisasm](http://github.com/acama/libxdisasm) library and currently supports generating ROP gadgets for x86, x86_64, arm, and soon ppc and mips.

Build Instructions:
-------------------
### Quick way
If you are on a 64-bit Linux machine and don't feel like building binutils from source, I have included the static libraries needed for the tool to compile. You can build the tool with:
```
make withstatic
```
### Longer way
First Build binutils with the appropriate flags. You can get the source from http://ftp.gnu.org/gnu/binutils/. By default binutils will install the shared libraries in /usr/local/lib. If this is not in your library path you might run into some issues. Run the following commands in the directory where you extracted the binutils archive.
```
./configure --enable-targets=all --enable-shared
make
sudo make install
```
Then you can build xrop. From the top level directory, run the following command:
```
make
```

Examples:
---------
Example output for x86_64 and ARM executables
<img src="http://i.imgur.com/HAgVLD0.png">
