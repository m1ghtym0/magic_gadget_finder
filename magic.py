#!/usr/bin/env python2
import r2pipe
import argparse
import sys
import re

# Just printing stuff
LINE = "----------------------------------------------"

class MagicSearcher(object):
    execve_calls = ['call sym.__GI_execve', 'call sym.execve']

    def __init__(self, libc, follow_depth, search_depth):
        self.r2 = r2pipe.open(libc)
        self.r2.cmd('aaa')
        self.follow_depth = follow_depth
        self.search_depth = search_depth

    # close r2pipe
    def quit(self):
        self.r2.quit()
    
    # find all /bin/sh strings in libc
    def search_bin_sh(self):
        output = self.r2.cmd('/ /bin/sh')
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
    
    # try to find magic gadget  with given /bin/sh strings
    def find_magic_gadget(self, bin_sh_offsets):
        for bin_sh in bin_sh_offsets:
            # get Xrefs to /bin/sh string
            refs = self.__get_refs(bin_sh)
            if not refs:
                return None
            for ref in refs:
                # check if execve is called with rdi->/bin/sh
                magic_offset = self.__check_execve(ref)
                if magic_offset:
                    return int(magic_offset, 16)
    
                # check if syscall is issued with rdi->/bin/sh
                magic_offset = self.__check_syscall(ref)
                if magic_offset:
                    return int(magic_offset, 16)
    
    
        return None

    # find all references to given offset
    def __get_refs(self, bin_sh_offset):
        # get Xrefs to /bin/sh string
        output = self.r2.cmd('axt @' + bin_sh_offset + self.bin_sh_ref)
        lines = output.split('\n')
        refs = []
        for line in lines:
            # extract offset of Xref
            ref = re.search(r'0x[0-9a-f]*', line)
            if ref:
                ref = ref.group(0)
                refs.append(ref)
        return refs
    

    
    # check if execve occurs with /bin/sh as first argument
    def __check_execve(self, ref):
        cmd = 'pd %d @' % self.search_depth
        output = self.r2.cmd(cmd + ref)
        lines = output.split('\n')
        for line in lines[1:]:
            offset, opcode, mnemonics = self.__parse_line(line)
            if not offset or not opcode or not mnemonics:
                continue
    
            # check if execve is called
            if any(execve in mnemonics for execve in self.execve_calls):
                magic_offset = self.__find_entry_execve(ref, offset)
                if magic_offset:
                    self.__print_gadget(magic_offset, offset)
                return magic_offset
    
            # check if rdi is modified -> magic won't happen anymore
            if self.bin_sh_register in mnemonics:
                return None
    
        return None
    
    # find entry to gadget where all arguments for execve will be set correctly
    def __find_entry_execve(self, ref, execve_offset):
        # registers that have to be set
        registers = self.execve_argument_registers
        # check registers
        return self.__follow_registers(execve_offset, ref, registers)
   
    # check if syscall occurs with /bin/sh as first argument
    def __check_syscall(self, ref):
        output = self.r2.cmd('pd 15 @ ' + ref)
        lines = output.split('\n')
        for line in lines[1:]:
            offset, opcode, mnemonics = self.__parse_line(line)
            if not offset or not opcode or not mnemonics:
                continue
            # check if syscall is issued
            if self.syscall in mnemonics:
                magic_offset =  self.__find_entry_syscall(ref, offset)
                if magic_offset:
                    self.__print_gadget(magic_offset, offset)
                return magic_offset
    
            # check if rdi is modified -> magic won't happen anymore
            if self.bin_sh_register in mnemonics:
                return None
    
        return None
   
    # find entry to gadget where all arguments for syscall will be set correctly
    def __find_entry_syscall(self, ref, syscall_offset):
        # registers that have to be set
        registers = self.syscall_argument_registers
        # check registers
        register_offset = self.__follow_registers(syscall_offset, ref, registers)
        # check for execve syscall 
        syscall_num_offset = self.__check_syscall_number(syscall_offset)
    
        if not register_offset or not syscall_num_offset:
            return None
    
        # return smallest offset
        if int(register_offset, 16) < int(syscall_num_offset, 16):
            return register_offset
        else:
            return syscall_num_offset
   
    # check if arguments are set correctly
    def __follow_registers(self, offset, ref, registers):
        for num_lines in range(10, self.follow_depth, 10):
            cmd = 'pd -%d @ ' % num_lines
            output = self.r2.cmd(cmd + offset)
            lines = output.split('\n')
    
            for line in lines[::-1]:
                offset, opcode, mnemonics = self.__parse_line(line)
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
                        for source in self.followed_registers:
                            if source in mnemonics[mnemonics.index(','):]:
                                registers.append(source)
                        # no more registers to follow -> done
                        if len(registers) == 0:
                            return offset
    
        print LINE
        print 'ERROR couldn\'t trace the following registers: ' + ",".join(registers)
        return None
   
    # check if correct execve syscall number is set 
    def __check_syscall_number(self, syscall_offset):
        for num_lines in range(10, self.follow_depth, 10):
            cmd = 'pd -%d @ ' % num_lines
            output = self.r2.cmd(cmd + offset)
            lines = output.split('\n')
            for line in lines[::-1]:
                offset, opcode, mnemonics = self.__parse_line(line)
                if not offset or not opcode or not mnemonics:
                    continue
    
                # can't follow jumps yet
                if 'jmp' in mnemonics:
                    return None
    
                # won't check push and pops yet
                if ',' not in mnemonics:
                    continue
    
                for reg in self.syscall_registers:
                    # check if register is modified
                    if reg in mnemonics[:mnemonics.index(',')]:
                        registers.remove(reg)
                        # check if the correct syscall number is set
                        if self.syscall_num_hex in mnemonics[mnemonics.index(','):] or self.syscall_num_dec in mnemonics[mnemonics.index(','):]:
                            return offset
                        # check if value derived from another register -> follow
                        for source in self.followed_registers:
                            if source in mnemonics[mnemonics.index(','):]:
                                registers.append(source)
                        # different syscall was set -> no magic happening
                        if len(registers) == 0:
                            return None
         
    
    # parse radare2 "pd" line
    def __parse_line(self, line):
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
    
    # print whole magic gadget code
    def __print_gadget(self, magic_offset, final_offset):
        diff = int(final_offset, 16) - int(magic_offset, 16)
        cmd = 'pId %d @ ' % (diff+1)
        print LINE
        print self.r2.cmd(cmd + magic_offset)


# TODO: not implemented yet
class MagicSearcherx86(MagicSearcher):
    # TODO libc using cdecl or fastcall?
    bin_sh_ref = '~mov [esp'
    bin_sh_register = '[esp]'
    followed_registers = ["eax", "ebx", "ecx", "edx", "edi", "esi"]
    # TODO libc using cdecl or fastcall?
    execve_argument_registers = ["[esp+4]", "[esp+8]"]
    syscall_argument_registers = ["rbx", "rcx"]
    syscall_num_registers = ["eax", "al"]
    sycall_num_hex = '0xb'
    sycall_num_dec = '11'
    syscall = 'int 0x80'

    def __init__(self, libc, follow_depth, search_depth):
        super(MagicSearcherx86, self).__init__(libc, follow_depth, search_depth)

class MagicSearcherx64(MagicSearcher):
    bin_sh_ref = '~lea rdi'
    bin_sh_register = 'rdi, '
    followed_registers = ["rax", "rbx", "rcx", "rdx", "rdi", "rsi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
                            "eax", "ebx", "ecx", "edx", "edi", "esi"]
    execve_argument_registers = ["rsi", "rdx"]
    syscall_argument_registers = ["rsi", "rdx"]
    syscall_num_registers = ["rax", "eax", "al"]
    sycall_num_hex = '0x3b'
    sycall_num_dec = '59'
    syscall = 'syscall'

    def __init__(self, libc, follow_depth, search_depth):
        super(MagicSearcherx64, self).__init__(libc, follow_depth, search_depth)

def main(argv):
    parser = argparse.ArgumentParser(description='Find the magic gadget.')
    parser.add_argument('libc', metavar='<libc.so>', help='Shared libc library')
    parser.add_argument('-A', choices=['x86', 'x86-64'], default='x86-64', help='Specify the architecture of the libc')
    parser.add_argument('-fD', '--follow-depth', default=40, type=int, help='Set the max. number of instructions to be followed when searching  \
                                                                    for the beginning of a magic gadget')
    parser.add_argument('-sD', '--search-depth', default=20, type=int,  help='Set the max. number of instrutions to be followed when searching  \
                                                                    for the execve or syscall after /bin/sh has been set as first argument')

    args = parser.parse_args()
    
    if args.A == 'x86-64':
        magic = MagicSearcherx64(args.libc, args.follow_depth, args.search_depth)
    elif args.A == 'x86':
        magic = MagicSearcherx86(args.libc, args.follow_depth, args.search_depth)
        
    # find all occurences of /bin/sh
    bin_sh_offsets = magic.search_bin_sh()
    # try to find magic gadget
    gadget_offset = magic.find_magic_gadget(bin_sh_offsets)

    if not gadget_offset:
        print LINE
        print 'Couldn\'t find a magic gadget:('
    else:
        print LINE
        print 'Here\'s your magic gadget:'
        print 'Offset: {0:#016x}'.format(gadget_offset)


    magic.quit()



if __name__ == "__main__":
    main(sys.argv[1:])
