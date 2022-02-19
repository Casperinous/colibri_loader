import ida_hexrays
from idautils import *
from idaapi import *
from idc import *


def decrypt_str(encr_buf_len,encr_buf_addr ,xor_key_len, xor_key_addr):
    s = bytearray(0)
    
    
    if encr_buf_len != 0 and encr_buf_addr != 0 and xor_key_len != 0 and xor_key_addr != 0:
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
        idc.set_cmt(address, text, 0)
        set_hexrays_comment(address, text)
    except:
        return


TARGET_FUNC = 0x15FBBF5

def find_and_decrypt_s(funcea):
    
    cfunc = idaapi.decompile(funcea)
    
    for item in cfunc.treeitems:
        op = item.op
        insn = item.cinsn
        expr = item.cexpr
        
        encr_buf_len = 0
        encr_buf_addr = 0
        xor_key_len = 0
        xor_key_addr = 0
        
        
        if op == ida_hexrays.cot_call:
            call_addr = idc.get_operand_value(item.ea,0)
            if call_addr == TARGET_FUNC:
                #print('[+] Found call at 0x%08x' % item.ea)
                args = expr.a
                for idx, arg in enumerate(args):
                    #print(idx,arg)
                    if arg.op == ida_hexrays.cot_num:
                        #print("[+] Idx=",idx,"is a num!")
                        if idx == 0:
                            encr_buf_len = arg.numval()
                            #print(hex(encr_buf_len))
                        if idx == 3:
                            xor_key_len = arg.numval()
                            #print(hex(xor_key_len))
                    if arg.op == ida_hexrays.cot_cast:
                        #print("[+] Idx=",idx,"is a cast!")
                        opc_idx = 0
                        if idc.print_insn_mnem(arg.ea) != "push":
                            opc_idx = 1
                        if idx == 1:
                            encr_buf_addr = idc.get_operand_value(arg.ea,opc_idx)
                            #print(hex(encr_buf_addr))
                        if idx == 2:
                            xor_key_addr = idc.get_operand_value(arg.ea,opc_idx)
                            #print(hex(xor_key_addr))
            
                s = decrypt_str(encr_buf_len,encr_buf_addr ,xor_key_len, xor_key_addr)
                print('[+] Found [%s] at 0x%08x' % (s.decode('utf-8'), item.ea))
                set_comment(item.ea,s.decode('utf-8'))



for funcea in idautils.Functions():
    print('[+] Funcea=0x%08x ' % funcea)
    #if funcea == 0x015fd613:
        #print('yes')
    find_and_decrypt_s(funcea)