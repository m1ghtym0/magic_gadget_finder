#!/usr/bin/env python2
import r2pipe
import argparse
import sys
import re

# Just printing stuff
LINE = "----------------------------------------------"

# Registers to be followed
REGISTERS_x86 = ["eax", "ebx", "ecx", "edx", "edi", "esi"]
REGISTERS_x64 = ["rax", "rbx", "rcx", "rdx", "rdi", "rsi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]

# Different calls to execve
EXECVE_CALLS = ['call sym.__GI_execve', 'call sym.execve' ]

# Registers for syscall number
SYSCALL_REGS = ["rax", "eax", "al"]
# syscall number for execve
SYSCALL_NUM = 0x3b

def search_bin_sh(r2):
    output = r2.cmd('/ /bin/sh')
    strings = output.split('\n')
    offsets = []
    print LINE
    for string in strings:
        # extract offset of /bin/sh string
        offset = re.search(r'0x[0-9a-f]*', string)
        if offset:
            offset = offset.group(0)
            print 'Found /bin/sh @ ' + offset
            offsets.append(offset)
    if not offsets:
        print 'Couldn\'t find any /bin/sh string'
    return offsets

def get_refs(r2, bin_sh):
    # get Xrefs to /bin/sh string
    output = r2.cmd('axt @' + bin_sh + ' ~lea rdi')
    lines = output.split('\n')
    refs = []
    for line in lines:
        # extract offset of Xref
        ref = re.search(r'0x[0-9a-f]*', line)
        if ref:
            ref = ref.group(0)
            refs.append(ref)
    return refs

def check(r2, bin_sh_offsets):
    for bin_sh in bin_sh_offsets:
        # get Xrefs to /bin/sh string
        refs = get_refs(r2, bin_sh)
        if not refs:
            return None
        for ref in refs:
            # check if execve is called with rdi->/bin/sh
            magic_offset = check_execve(r2, ref)
            if magic_offset:
                return int(magic_offset, 16)

            # check if syscall is issued with rdi->/bin/sh
            magic_offset = check_syscall(r2, ref)
            if magic_offset:
                return int(magic_offset, 16)


    return None

def check_execve(r2, ref):
    # TODO: set depth with commandline
    output = r2.cmd('pd 20 @ ' + ref)
    lines = output.split('\n')
    for line in lines[1:]:
        offset, opcode, mnemonics = parse_line(line)
        if not offset or not opcode or not mnemonics:
            continue

        # check if execve is called
        if any(execve in mnemonics for execve in EXECVE_CALLS):
            magic_offset = check_execve_magic(r2, ref, offset)
            if magic_offset:
                print_gadget(r2, magic_offset, offset)
            return magic_offset

        # check if rdi is modified -> magic won't happen anymore
        if 'rdi ,' in mnemonics:
            return None

    return None

def check_execve_magic(r2, ref, execve_offset):
    # registers that have to be set
    registers = ["rsi", "rdx"]
    # check registers
    return check_registers(r2, execve_offset, ref, registers)

def check_syscall(r2, ref):
    output = r2.cmd('pd 15 @ ' + ref)
    lines = output.split('\n')
    for line in lines[1:]:
        offset, opcode, mnemonics = parse_line(line)
        if not offset or not opcode or not mnemonics:
            continue
        # check if syscall is issued
        if 'syscall' in mnemonics:
            magic_offset =  check_syscall_magic(r2, ref, offset)
            if magic_offset:
                print_gadget(r2, magic_offset, offset)
            return magic_offset

        # check if rdi is modified -> magic won't happen anymore
        if 'rdi ,' in mnemonics:
            return None

    return None

def check_syscall_magic(r2, ref, syscall_offset):
    # registers that have to be set
    registers = ["rsi", "rdx"]
    # check registers
    register_offset = check_registers(r2, syscall_offset, ref, registers)
    # check for execve syscall 
    rax_offset = check_syscall_number(r2, syscall_offset)

    if not register_offset or not rax_offset:
        return None

    # return smallest offset
    if int(register_offset, 16) < int(rax_offset, 16):
        return register_offset
    else:
        return rax_offset

def check_registers(r2, offset, ref, registers):
    # TODO: get range from commandline
    for num_lines in range(10, 40, 10):
        cmd = 'pd -%d @ ' % num_lines
        output = r2.cmd(cmd + offset)
        lines = output.split('\n')

        for line in lines[::-1]:
            offset, opcode, mnemonics = parse_line(line)
            if not offset or not opcode or not mnemonics:
                continue
            
            # can't follow jumps yet
            if 'jmp' in mnemonics:
                return None

            # won't check push and pops yet
            if ',' not in mnemonics:
                continue
            
            for reg in registers:
                # check if register is modified
                if reg in mnemonics[:mnemonics.index(',')]:
                    registers.remove(reg)
                    # check if value derived from another register -> follow
                    for source in REGISTERS_x64:
                        if source in mnemonics[mnemonics.index(','):]:
                            registers.append(source)
                    for source in REGISTERS_x86:
                        if source in mnemonics[mnemonics.index(','):]:
                            registers.append(source)

                    # no more registers to follow -> done
                    if len(registers) == 0:
                        return offset

    print LINE
    print 'ERROR couldn\'t trace the following registers: ' + ",".join(registers)
    return None

def check_syscall_number(r2, syscall_offset):
    for num_lines in range(10, 40, 10):
        cmd = 'pd -%d @ ' % num_lines
        output = r2.cmd(cmd + offset)
        lines = output.split('\n')
        for line in lines[::-1]:
            offset, opcode, mnemonics = parse_line(line)
            if not offset or not opcode or not mnemonics:
                continue

            # can't follow jumps yet
            if 'jmp' in mnemonics:
                return None

            # won't check push and pops yet
            if ',' not in mnemonics:
                continue

            for reg in SYSCALL_REGS:
                # check if register is modified
                if reg in mnemonics[:mnemonics.index(',')]:
                    registers.remove(reg)
                    # check if the correct syscall number is set
                    if str(SYSCALL_NUM_HEX) in mnemonics[mnemonics.index(','):] or str(SYSCALL_NUM_DEC) in mnemonics[mnemonics.index(','):]:
                        return offset
                    # check if value derived from another register -> follow
                    for source in REGISTERS_x64:
                        if source in mnemonics[mnemonics.index(','):]:
                            registers.append(source)
                    for source in REGISTERS_x86:
                        if source in mnemonics[mnemonics.index(','):]:
                            registers.append(source)
                    
                    # different syscall was set -> no magic happening
                    if len(registers) == 0:
                        return None
     

def parse_line(line):
    # parse radare2 "pd" line
    parts = re.search(r'(0x[0-9a-f]*)([ ]*)([0-9a-f]*)([ .]*)([a-zA-Z0-9,._ \+\-\*\[\]\(\)]*)', line)
    if not parts:
        return None, None, None
    if parts.group(1) and parts.group(3) and parts.group(5):
        offset = parts.group(1)
        opcode = parts.group(3)
        mnemonics = parts.group(5)
    else:
        return None, None, None

    return offset, opcode, mnemonics

def print_gadget(r2, magic_offset, final_offset):
    # print whole magic gadget code
    diff = int(final_offset, 16) - int(magic_offset, 16)
    cmd = 'pId %d @ ' % (diff+1)
    print LINE
    print r2.cmd(cmd + magic_offset)

def main(argv):
    parser = argparse.ArgumentParser(description='Find the magic gadget.')
    parser.add_argument('libc', metavar='<libc.so>', help='Shared libc library')

    args = parser.parse_args()
    try:
        # open binary
        r2 = r2pipe.open(args.libc)
    except Exception, e:
        print e.message
        sys.exit(1)
   
    # analyse binary
    r2.cmd('aaa')
    # find all occurences of /bin/sh
    bin_sh_offsets = search_bin_sh(r2)
    # try to find magic gadget
    gadget_offset = check(r2, bin_sh_offsets)
    if not gadget_offset:
        print LINE
        print 'Couldn\'t find a magic gadget:('
    else:
        print LINE
        print 'Here\'s your magic gadget:'
        print 'Offset: {0:#016x}'.format(gadget_offset)

    # close binary
    r2.quit()


if __name__ == "__main__":
    main(sys.argv[1:])
