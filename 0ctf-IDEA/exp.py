#!/usr/bin/python -i

from pwn import process

r = process("./eshell")

print r.recvuntil("out\n")

ports_data = r.recvuntil("prelogue END\n")
print ports_data

ports = [[int(j) for j in i.split()] for i in ports_data.split('\n')[:64]]

in_ports = [ports[i][1] for i in range(64)]
out_ports = [ports[i][2] for i in range(64)]

endian_in = range(8, 16) + range(8)
add_in = [in_ports[i + 16] for i in endian_in]

AND_GATE = 1
OR_GATE = 2
XOR_GATE = 3
MUX_GATE = 4


def start(i):
    assert isinstance(i, int)
    return 'o ' + str(i) + '\n'


def go(op, t, con):
    con_int = ['null', 'pro', 'con'].index(con)
    assert isinstance(t, int)
    arg = t + (con_int << 8)
    return op + ' ' + str(arg) + '\n'


def go_up(t, con='null'):
    return go('p', t, con)


def go_dn(t, con='null'):
    return go('q', t, con)


def go_side(t, con='null'):
    return go('r', t, con)


def go_back():
    return "t 0\n"


def output():
    return "s 0\n"


def jend():
    return "u\n"


def traverse_adder():
    midpl = ''
    midpl += go_back()
    midpl += go_dn(OR_GATE)
    midpl += go_side(XOR_GATE)
    midpl += go_up(XOR_GATE, 'con')
    midpl += go_dn(AND_GATE)
    midpl += go_up(AND_GATE, 'pro')
    midpl += output()

    pl = ''
    pl += go_dn(AND_GATE)
    pl += go_up(AND_GATE, 'pro')
    pl += output()
    pl += midpl * 15
    # go to output0
    pl += go_back() * (4 * 15 + 2)
    pl += go_dn(XOR_GATE)
    pl += go_dn(XOR_GATE)
    return pl


pl = ''
pl += start(in_ports[24])

pl += (traverse_adder() + go_dn(XOR_GATE)) * 8
pl += traverse_adder()

pl += jend()
r.send(pl)

rcv = r.recvuntil('END')
print rcv
print r.recvuntil('END\n')

rcv = [int(i) for i in rcv.split()[:-1]]

assert len(rcv) == 128 + 16

pl = ''
pl += start(in_ports[40])

pl += (traverse_adder() + go_dn(XOR_GATE)) * 8
pl += traverse_adder()

pl += jend()
r.send(pl)

rcv2 = r.recvuntil('END')
print rcv2
print r.recvuntil('END\n')

rcv2 = [int(i) for i in rcv2.split()[:-1]]

assert len(rcv2) == 128 + 16

hex1 = int(''.join([str(i) for i in rcv[::-1]]), 2)
hex2 = int(''.join([str(i) for i in rcv2[::-1]]), 2)

print hex(hex1)
print hex(hex2)
'''
pl = ''
pl += start(in_ports[56])

pl += (traverse_adder() + go_dn(XOR_GATE)) * 8

pl += jend()
r.send(pl)
r.interactive()
'''


def key_bits(g):
    #return [(i - (j / 8) * 25 + (j % 8) * 16) % 64 for i in range(16)]
    root = range(
        128) * 2  #[(i) + j * 16 for j in range(8) for i in range(16)] * 2
    offset = ((g / 8) * 25 + (g % 8) * 16) % 128
    return root[offset:offset + 16][::-1]


key = [-1] * 128

key_id = [i + j * 12 for j in range(4) for i in [1, 8]] + [49]

pos = [j for i in key_id for j in key_bits(i)]

#pos = [(i + (j / 8) * 25 - (j % 8) * 16) % 128
#       for j in range(1, 1 + 6 * 8, 6) for i in range(16)]

for i in range(128):
    ip = pos[i]
    if key[ip] == -1:
        key[ip] = rcv[i]
    else:
        if key[ip] != rcv[i]:
            print 'ip=', ip
            print 'i=', i
            print key[ip], '!=', rcv[i]

print key

key_id = [i + j * 12 for j in range(4) for i in [2, 7]] + [50]

pos = [j for i in key_id for j in key_bits(i)]

#pos = [(i + (j / 8) * 25 - (j % 8) * 16) % 128
#       for j in range(1, 1 + 6 * 8, 6) for i in range(16)]

for i in range(128):
    ip = pos[i]
    if key[ip] == -1:
        key[ip] = rcv2[i]
    else:
        if key[ip] != rcv2[i]:
            print 'ip=', ip
            print 'i=', i
            print key[ip], '!=', rcv2[i]
print key
#r.interactive()
