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
import ninja

def find_guid(st, instr, load_addr):
    opr0 = load_addr.operands[0]
    opr1 = load_addr.operands[1]

    if opr0.operation == LowLevelILOperation.LLIL_REG and opr1.operation == LowLevelILOperation.LLIL_CONST:
        if opr1.operands[0] == 0x140:
            rcx = ninja.try_get_register_value(instr, 'rcx')
            if rcx != None:
                ninja.check_pattern(st, instr, rcx)
