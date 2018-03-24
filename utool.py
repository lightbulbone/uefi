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
else:
    cpath = None

if cpath != None:
    do_search(cpath, search_pattern)
else:
    do_search(os.getcwd())
