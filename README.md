xrop
=======

xrop is a simple tool to generate ROP gadgets. It supports PE, ELF, Mach-O and perhaps other executable formats. It uses the [libxdisasm](http://github.com/acama/libxdisasm) library and currently supports generating ROP gadgets for x86, x86_64, arm, ppc, mips, riscv, sh4 and sparc.

Build Instructions
-------------------

On macos there is a Homebrew tap available:
```
brew tap acama/homebrew-xrop
brew install xrop
```

On other systems, you need to build from source as of now:
```
git clone https://github.com/acama/xrop.git
cd xrop
git submodule update --init --recursive
make
sudo make install # will install in /opt/xrop
```

Changelog
---------
* v1.2 - macos (apple silicon) support.
* v1.1 - call gadgets, jmp gadgets, printing instruction opcodes.

Examples
---------
Example output for x86_64 and ARM executables
<img src="http://i.imgur.com/HAgVLD0.png">
