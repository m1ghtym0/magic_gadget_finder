## Finding the magic gadget

# The magic gadget (AMD64)

Basically the magic gadget is some code residing
in the libc and when executed is opening a shell.
This can be used when trying to do a [ret2libc][ret2libc]
in a [ROP][rop]-style-exploit.

The magic gadget code has to call execve or issue the corresponding 
syscall directly, while /bin/sh is set as first argument.

Overview:
    * execve
        + rdi: Pointer to /bin/sh
        + rsi: Pointer to argv
        + rdx: Pointer to env

    * syscall
        + rax: Syscallnumber of execve: 59 oder 0x3b
        + rdi: Pointer to /bin/sh
        + rsi: Pointer to argv
        + rdx: Pointer to env

# magic.py

Is a little python-script that uses [radare2][r2] and [r2pipe-python][r2pipe],
to find such magic gadgets automatically for a given libc.
    $ ./magic.py libc-2.19.so
    [x] Analyze all flags starting with sym. and entry0 (aa)
    [x] Analyze len bytes of instructions for references (aar)
    [x] Analyze function calls (aac)
    [*] Use -AA or aaaa to perform additional experimental analysis.
    [x] Constructing a function name for fcn.* and sym.func.* functions (aan)
    Searching 7 bytes from 0x00000270 to 0x003aaa20: 2f 62 69 6e 2f 73 68 
    Searching 7 bytes in [0x270-0x3aaa20]
    hits: 1
    ----------------------------------------------
    Found /bin/sh @ 0x001639a0
    ----------------------------------------------
    0x00041374   488b052d3b3600  mov rax, qword [rip + 0x363b2d]
    0x0004137b   488d3d1e261200  lea rdi, qword [rip + 0x12261e]
    0x00041382       488d742430  lea rsi, qword [rsp + 0x30]
    0x00041387 c7052f61360000000000  mov dword [rip + 0x36612f], 0
    0x00041391 c7052961360000000000  mov dword [rip + 0x366129], 0
    0x0004139b           488b10  mov rdx, qword [rax]
    0x0004139e       e86d8f0700  call sym.execve
    
    ----------------------------------------------
    Here's your magic gadget:
    Offset: 0x00000000041374

Unfortunately, at the moment magic.py only works with 64-bit libraries on x86.


# TODO
    * Cleanup the code
    * Add commandline option for search-depth
    * Extend for 32-Bit libraries
    * Test with more libcs


[r2]: http://www.radare.org/
[r2pipe]: https://github.com/radare/radare2-bindings/tree/master/r2pipe/python
[ret2libc]: https://en.wikipedia.org/wiki/Return-to-libc_attack
[rop]: https://en.wikipedia.org/wiki/Return-oriented_programming


