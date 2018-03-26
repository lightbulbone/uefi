#!/usr/bin/env python

from binaryninja import *
import binascii
import fnmatch
import sys
import os

# --- test/debug functions ---

def pdir(o):
    for d in dir(o):
        print(d)

def ptype(o):
    print(type(o))

class InterfaceFinder():
    """
        @class: InterfaceFinder
        @description:
            This class searches calls to EFI methods used to install
            protocols for the GUID given as `pattern`.  This pattern
            match does not attempt to handle endianness at all so the 
            pattern must be given in the corresponding endianness
            (usually little endian).
    """

    def __init__(self, pattern):
        self._pattern = pattern

    def search(self, path):
        """
            @function: search
            @description:
                Search the UEFI binary at the given path.

            This is the main entry point to this class.
        """

        self._path = path
        self._bv = binaryview.BinaryViewType['PE'].open(self._path)
        self._bv.update_analysis_and_wait()
        for func in self._bv.functions:
            for bb in func.low_level_il.basic_blocks:
                for instr in bb:
                    if instr.operation == LowLevelILOperation.LLIL_CALL:
                        call_target = instr.operands[0]
                        if call_target.operation == LowLevelILOperation.LLIL_LOAD:
                            load_addr = call_target.operands[0]
                            if load_addr.operation == LowLevelILOperation.LLIL_ADD:
                                self._find_protocol(instr, load_addr)
                                self._find_multiple(func, instr, load_addr)

    def _try_get_reg_value(self, instr, reg):
        mrv = instr.get_reg_value(reg)
        try:
            v = mrv.value
        except AttributeError:
            v = None
        return v

    def _check_pattern(self, instr, reg_val):
        hv = binascii.hexlify(self._bv.read(reg_val, 16))
        if hv.startswith(self._pattern):
            print("Found candidate:")
            print("\tFile: %s" % self._path)
            print("\tCall site: 0x%x" % instr.address)

    def _get_bytes(self, ptr, sz):
        v = self._bv.read(ptr, sz)
        return binascii.hexlify(v)

    def _find_protocol(self, instr, load_addr):
        """ 
            @function: InterfaceFinder._find_protocol
            @description:
                Searches calls to EFI_BOOT_SERVICES_TABLE.InstallProtocolInterface
                for a GUID matching the pattern provided to InterfaceFinder.__init__()
        """


        opr0 = load_addr.operands[0]
        opr1 = load_addr.operands[1]
        if opr0.operation == LowLevelILOperation.LLIL_REG and opr1.operation == LowLevelILOperation.LLIL_CONST:
            if opr1.operands[0] == 0x80:
                rdx = self._try_get_reg_value(instr, 'rdx')
                if rdx != None:
                    self._check_pattern(instr, rdx)

    def _find_multiple(self, func, instr, load_addr):
        """ 
            @function: InterfaceFinder._find_multiple
            @description:
                Searches calls to EFI_BOOT_SERVICES_TABLE.InstallMultipleProtocolInterfaces
                for a GUID matching the pattern provided to InterfaceFinder.__init__()
        """

        opr0 = load_addr.operands[0]
        opr1 = load_addr.operands[1]
        if opr0.operation == LowLevelILOperation.LLIL_REG and opr1.operation == LowLevelILOperation.LLIL_CONST:
            if opr1.operands[0] == 0x148:
                rdx = self._try_get_reg_value(instr, 'rdx') # guid 1
                r8  = self._try_get_reg_value(instr, 'r8')  # interface 1
                r9  = self._try_get_reg_value(instr, 'r9')  # guid 2 or zero

                self._check_pattern(instr, rdx)

                if r9 == None or r9 == 0:
                    return
                else:
                    self._walk_stack(func, instr)

    def _walk_stack(self, func, call_instr):
        """ 64-bit UEFI uses the Microsoft 64-bit calling convention. The first
            four integer args are passed in RCX, RDX, R8, and R9.  Remaining integer
            arguments are passed on the stack.  The ABI also requires that the
            caller allocate space for these registers to be saved by the callee, this
            space is referred to as the "shadow stack".

            See: https://msdn.microsoft.com/en-us/library/ms235286.aspx

            0x28 parameter 5          GUID 3
            0x20 parameter 4
            0x18 shadow store 3 (R9)  GUID 2
            0x10 shadow store 2 (R8)
            0x08 shadow store 1 (RDX) GUID 1
            0x00 shadow store 0 (RCX) 
        """
        mrv = func.get_reg_value_at(call_instr.address, 'rsp')

        param_offset = 0x20
        while True:
            param = mrv.offset + param_offset
            msv = func.get_stack_contents_at(call_instr.address, param, 8)

            try:
                sv = msv.value
            except AttributeError:
                sv = None

            if sv == None or sv == 0:
                break

            if (param_offset & 0xf) == 0x8:
                self._check_pattern(call_instr, sv)

            param_offset += 0x8

search_pattern = sys.argv[1]
finder = InterfaceFinder(search_pattern)

if len(sys.argv) == 3:
    cp = sys.argv[2]
    finder.search(cp)
else:
    for (dirpath, dirnames, filenames) in os.walk(os.getcwd()):
        for fn in filenames:
            if fnmatch.fnmatch(fn, '*.pe'):
                candidate_path = os.path.join(dirpath, fn)
                finder.search(candidate_path)
