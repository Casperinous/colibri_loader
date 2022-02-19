import idautils
import idc
import idaapi
import struct

# Obviously change this to yours
FUNC_DECR = 0x1875ABF

def get_encr_buf(addr):
    r = 0x0
    while True:
        addr = idc.prev_head(addr)
        if idc.print_insn_mnem(addr) == "mov":
            if idc.print_operand(addr,0) == "esi":
               if idc.get_operand_type(addr, 1) == 5:
                r = idc.get_operand_value(addr,1)
                break
    return r    
    

def decrypt_str(addr):
    s = bytearray(0)
    encr_buf_len = idaapi.get_dword(addr + 0x4)
    encr_buf_addr = idaapi.get_dword(addr)
    
    xor_key_len = idaapi.get_dword(addr + 0xC)
    xor_key_addr = idaapi.get_dword(addr+0x8)
    
    for i in range(0, encr_buf_len):
        idx = i % xor_key_len
        ch = (idaapi.get_word(encr_buf_addr + i*2) ^ idaapi.get_word(xor_key_addr + idx*2)) & 0xff
        s.append(ch)
    
    return s
    
    
def set_hexrays_comment(address, text):
    '''
    set comment in decompiled code
    '''
    cfunc = idaapi.decompile(address)
    tl = idaapi.treeloc_t()
    tl.ea = address
    tl.itp = idaapi.ITP_SEMI
    cfunc.set_user_cmt(tl, text)
    cfunc.save_user_cmts() 
    
    
def set_comment(address, text):
    try:
        ## Set in dissassembly
        idc.set_cmt(address, text,0)
        ## Set in decompiled data
        set_hexrays_comment(address, text)
    except:
        print("Can't set comments")
        return
    
    


for xref in idautils.XrefsTo(FUNC_DECR):
    encr_buf_addr = get_encr_buf(xref.frm)
    s = decrypt_str(encr_buf_addr)
    print("Found string %s at 0x%08x" % (s.decode('utf-8'), encr_buf_addr))
    set_comment(xref.frm, s.decode('utf-8'))