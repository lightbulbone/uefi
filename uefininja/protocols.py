#
#   @file: find-guid.py
#
#   @description:
#       Search all *.pe files in the tree rooted in the current directory for a call to
#       EFI_BOOT_SERVICES.LocateProtocol().  The partial GUID (see @usage) is
#       assumed to be the initial bytes (in hex) of the GUID.  The GUID should be written
#       in little-endian order.
#
#   @usage:
#       python ./find-guid.py [partial-guid]
#
#   @examples:
#       find-guid.py 5a7e40176cafe8 ./MBP133_0233_B00.fd/regions/region-bios/volume-0/file-2ad3de79-63e9-9b4f-b64f-e7c6181b0cec/section1/section1/volume-ee4e5898-3914-4259-9d6e-dc7bd79403cf/file-d08e7171-89fb-4b7d-9ba9-ca263319ac35/section1.pe
#       find-guid.py 5a7e40176cafe8 ./MBP133_0233_B00.fd/regions/region-bios/volume-0/file-2ad3de79-63e9-9b4f-b64f-e7c6181b0cec/section1/section1/volume-ee4e5898-3914-4259-9d6e-dc7bd79403cf/file-408edcec-cf6d-477c-a5a8-b4844e3de281/section0.pe
#

from binaryninja import *
from . import ninja

BOOTSERVICES_INSTALL_PROTOCOL_INTERFACE = 0x80
BOOTSERVICES_INSTALL_MULTIPLE_PROTOCOL_INTERFACES = 0x148

def find_guid(st, instr, load_addr):
    opr0 = load_addr.operands[0]
    opr1 = load_addr.operands[1]

    if opr0.operation == LowLevelILOperation.LLIL_REG and opr1.operation == LowLevelILOperation.LLIL_CONST:
        if opr1.operands[0] == BOOTSERVICES_INSTALL_PROTOCOL_INTERFACE:
           rdx = ninja.try_get_register_value(instr, 'rdx') 
           if rdx is not None:
                ninja.check_pattern(st, instr, rdx)
        elif opr1.operands[0] == BOOTSERVICES_INSTALL_MULTIPLE_PROTOCOL_INTERFACES:
            rdx = ninja.try_get_register_value(instr, 'rdx')
            r8  = ninja.try_get_register_value(instr, 'r8')
            r9  = ninja.try_get_register_value(instr, 'r9')

            ninja.check_pattern(st, instr, rdx)

            if r9 == None or r9 == 0:
                return
            else:
                _walk_stack(st, instr)

def _walk_stack(st, call_instr):
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
    func = st.get_function()
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
            ninja.check_pattern(st, call_instr, sv)

        param_offset += 0x8
