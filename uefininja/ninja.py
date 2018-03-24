from binaryninja import *
import binascii
import state

def open(path, view_type = 'PE'):
    bv = binaryview.BinaryViewType[view_type].open(path)
    st = state.AnalysisState(bv, path)
    return st

def analyze(st, timeout = 10):
    import threading
    import time

    st.get_binary_view().add_analysis_option("linearsweep")
    t = threading.Thread(st._bv.update_analysis())
    slices = int(timeout / 0.1)
    ret = False

    t.start()
    while True:
        if st._bv.analysis_progress.state == AnalysisState.IdleState:
            ret = True
            break
        elif slices == 0:
            ret = False
            break
        slices -= 1
        time.sleep(0.1)

    return ret

def search_calls(st, proc, patt):
    st.set_pattern(patt)

    for func in st.get_binary_view().functions:
        for bb in func.low_level_il.basic_blocks:
            for instr in bb:
                if instr.operation == LowLevelILOperation.LLIL_CALL:
                    call_target = instr.operands[0]
                    if call_target.operation == LowLevelILOperation.LLIL_LOAD:
                        load_addr = call_target.operands[0]
                        if load_addr.operation == LowLevelILOperation.LLIL_ADD:
                            proc(st, instr, load_addr)

def try_get_register_value(instr, reg):
    mrv = instr.get_reg_value(reg)
    try:
        v = mrv.value
    except AttributeError:
        v = None
    return v

def check_pattern(st, instr, reg_val):
    hv = binascii.hexlify(st.get_binary_view().read(reg_val, 16)).lower()
    if hv.startswith(st.get_pattern()):
        print("Found candidate:")
        print("\tFile: %s" % st.get_path())
        print("\tCall site: 0x%x" % instr.address)

def get_bytes(st, ptr, sz):
    v = st.get_binary_view().read(ptr, sz)
    return binascii.hexlify(v)
