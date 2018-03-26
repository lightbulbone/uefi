#
#   @file: utool.py
#
#   @description:
#       UEFI tool to assist in finding protocol definitions.
#
#   @usage:
#       python2 ./utool.py [partial-guid]
#
#   @examples:
#       utool.py 5a7e40176cafe8 ./path/to/file-d08e7171-89fb-4b7d-9ba9-ca263319ac35/section1.pe
#       utool.py 5a7e40176cafe8 ./path/to/file-408edcec-cf6d-477c-a5a8-b4844e3de281/section0.pe
#

import uefininja
import fnmatch
import sys
import os

def do_search(cp, sp):
    def __search(_cp, _sp):
        st = uefininja.ninja.open(_cp)
        if uefininja.ninja.analyze(st, 30) == False:
            print("Analysis error: %s" % _cp)

        uefininja.ninja.search_calls(st, uefininja.protocols.find_guid, _sp)

    if os.path.isdir(cp):
        for (dirpath, dirnames, filenames) in os.walk(cp):
            for fn in filenames:
                if fnmatch.fnmatch(fn, '*.pe'):
                    fcp = os.path.join(dirpath, fn)
                    __search(fcp, sp)
    else:
        __search(cp, sp)

search_pattern = sys.argv[1]
if len(sys.argv) == 3:
    cpath = sys.argv[2]
    do_search(cpath, search_pattern)
else:
    do_search(os.getcwd(), search_pattern)
