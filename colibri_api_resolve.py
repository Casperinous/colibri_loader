import idaapi
import idc
import idautils
import ida_bytes
import struct
import pefile

dlls = [
    "kernel32.dll",
    "user32.dll",
    "ntdll.dll",
    "shlwapi.dll",
    "iphlpapi.dll",
    "urlmon.dll",
    "ws2_32.dll",
    "crypt32.dll",
    "shell32.dll",
    "advapi32.dll",
    "gdiplus.dll",
    "gdi32.dll",
    "ole32.dll",
    "psapi.dll",
    "cabinet.dll",
    "imagehlp.dll",
    "netapi32.dll",
    "wtsapi32.dll",
    "mpr.dll",
    "wininet.dll",
    "userenv.dll",
    "bcrypt.dll",
]

def parse_dll_exports(dll_name):
    api_names = []
    # https://github.com/phracker/HopperScripts/blob/master/list-pe-exports.py
    filename = os.path.join("C:\\Windows\\System32", dll_name)
    print("reading imports from %s" % filename)  
    if not os.path.exists(filename):
        print("Failed to locate DLL %s" % filename)
        return api_names
    pe = pefile.PE(filename, fast_load=True)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
    
    for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if export.name is not None:
            api_names.append(export.name.decode('utf-8'))
    return api_names

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

def get_hash(addr):
    cur_addr = addr

    hashes = []
    i = 0
    while True and i < 32:
        cur_addr = prev_head(cur_addr)
        if idc.print_insn_mnem(cur_addr) == "mov":
            if idc.print_operand(cur_addr,0) == "edx":
                return idc.get_operand_value(cur_addr, 1)
        i += 1

    return 0
    
def word(buf):
    buf = struct.unpack('2s', buf)[0]
    return struct.unpack('<H', buf)[0]

def byte(buf):
    buf = struct.unpack('1s', buf)[0]
    return struct.unpack('<B    ', buf)[0]

def hasher(s):
    s = bytearray(s, 'utf-8')
    
    '''
    name = s + b'\x00'
    s = name
    print (s)
    '''
    s_len = len(s)
    idx = 0
    hash = 0
    
    cur_len = s_len >> 2
    while cur_len != 0:
        
        cur_16b = word(s[idx:idx+2]) + hash
        xor_16b = word(s[idx+2:idx+4])
        
        
        
        op1 = (0x20 * cur_16b) & 0xffffffff
        op2 = (op1 ^ xor_16b) & 0xffffffff
        op3 = (op2 << 11) & 0xffffffff
        op4 = (op3 ^ cur_16b) & 0xffffffff
        op5 = (op4 >> 11) & 0xffffffff
        
        hash = (op5 + op4) & 0xffffffff
        
        cur_len -= 1
        idx += 4      
        
    rem = s_len & 3           
    if rem == 1:
        op1 = (s[idx] + hash) & 0xffffffff
        op2 = (op1 << 10) & 0xffffffff
        
        tmp1 = (op1 ^ op2) & 0xffffffff
        tmp2 = (tmp1 >> 1) & 0xffffffff
        hash = (tmp1 + tmp2) & 0xffffffff
    elif rem == 2:
        op1 = (word(s[idx:idx+2]) + hash) & 0xffffffff
        op2 = (op1 << 11) & 0xffffffff
        
        tmp1 = (op2 ^ op1) & 0xffffffff
        tmp2 = (tmp1 >> 17) & 0xffffffff
        hash = (tmp1 + tmp2) & 0xffffffff
        
    elif rem == 3:
        op1 = (word(s[idx:idx+2]) + hash) & 0xffffffff
        op2 = ((s[idx+2])*4) & 0xffffffff
        op3 = (op1 ^ op2) & 0xffffffff
        op4 = (op3 << 16) & 0xffffffff
        
        tmp1 = (op4 ^ op1) & 0xffffffff
        tmp2 = (tmp1 >> 11) & 0xffffffff
        hash = (tmp1 + tmp2) & 0xffffffff

    op1 = (8 * hash) & 0xffffffff
    op2 = (op1 ^ hash) & 0xffffffff
    op3 = (op2 >> 5) & 0xffffffff
    
    tmp1 = (op3 + op2) & 0xffffffff
    
    
    op4 = (16 * tmp1) & 0xffffffff
    op5 = (op4 ^ tmp1) & 0xffffffff
    op6 = (op5 >> 17) & 0xffffffff
    
    tmp2 = (op6 + op5) & 0xffffffff
        
    op7 = (tmp2 << 25) & 0xffffffff
    op8 = (op7 ^ tmp2) & 0xffffffff
    op9 = (op8 >> 6) & 0xffffffff
    
    return (op8 + op9) & 0xffffffff
        

def auto_analyse(resolver_addr):
    print("-----------------------------------------------------------------------------------")
    total_exports = []
    hash_lookup = {}
    for dll_name in dlls:
        exports = parse_dll_exports(dll_name)
        total_exports += exports

    for export in total_exports:
        resulting_hash = hasher(export)
        hash_lookup[resulting_hash] = export
    
    
    for x in idautils.XrefsTo(resolver_addr):
        api_hash = get_hash(x.frm)
        print('[-] Found hash 0x%08x at 0x%08x' % (api_hash, x.frm))
        if api_hash in hash_lookup:
            print("[+] Hash 0x%s resolved to -> %s" % (api_hash, hash_lookup[api_hash]))
            set_comment(x.frm, hash_lookup[api_hash])





'''        
s = bytes('AppCacheGetFallbackUrl', 'utf8')

print (hex(calc_api_hash(s)))
'''

