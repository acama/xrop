xrop
=======

xrop is a simple tool to generate ROP gadgets. It supports PE, ELF, Mach-O and perhaps other executable formats. It uses the [libxdisasm](http://github.com/acama/libxdisasm) library and currently supports generating ROP gadgets for x86, x86_64, arm, ppc and mips.

Build Instructions:
-------------------
```
cd xrop
git submodule update --init --recursive
make
```

Examples:
---------
Example output for x86_64 and ARM executables
<img src="http://i.imgur.com/HAgVLD0.png">
