#!/usr/bin/python -i

target = 'a4b0d91746391500f872'

flag_content = '01234567891123456789'
flag_list = [135, 95, 158, 223, 249, 128, 188, 120, 123, 167]
flag_content = ''.join('%02x' % i for i in flag_list)

with open('dump.bin', 'rb') as f:
    raw = f.read()

lut = [[raw[(i*256+j)*10:(i*256+j+1)*10]for j in range(256)]for i in range(10)]


def xor(a, b):
    # print 'rxor', b.encode('hex')
    return ''.join(chr(ord(i) ^ ord(j)) for i, j in zip(a, b))


def enc(x):
    y = lut[0][0]
    for i in range(10):
        y = xor(y, lut[i][ord(x[i])])
    return y


if enc(flag_content.decode('hex')).encode('hex') == target:
    print 'flag:'
    print 'flag{'+flag_content+'}'
    #exit(0)


def b2i(s):
    return sum(j << (i*8)for i, j in enumerate(bytearray(s)))


luti = [map(b2i, i)for i in lut]

target_arr = b2i(xor(target.decode('hex'),lut[0][0]))

# m=Matrix(GF(2),2561,80,[[1&(vfs[i]>>j)for j in range(2561)]for i in range(80)])

arr = [[1 & (luti[j][k] >> i)for j in range(10)
        for k in range(256)]+[1 & (target_arr >> i)]for i in range(80)]

m = Matrix(GF(2), 80, 2561, arr)

mm = m.echelon_form()


def first_one(l):
    for i in range(len(l)):
        if l[i] == 1:
            return i
    return len(l)


mm_fos = [(first_one(i)//256) for i in mm]


def sat(depth, sol):
    y = (mm[depth][2560])
    for i, j in enumerate(sol):
        y += mm[depth][(9-i)*256+j]
    # print 'sat:', y
    return long(y) == 0


def dfs(depth=80, sol=None):
    if sol is None:
        sol = []
    if depth == 0:
        yield sol[::-1]
    else:
        line = mm[depth-1]
        fo = 10-mm_fos[depth-1]
        # print 'fo',fo
        # print 'sol',sol
        if fo == len(sol):
            if sat(depth-1, sol):
                for i in dfs(depth-1, sol):
                    yield i
        else:
            for i in range(256):
                for j in dfs(depth, sol+[i]):
                    yield j


for i in dfs():
    print 'solution', i

# print mm
"""
def xor(a, b):
    # print 'rxor', b.encode('hex')
    return ''.join(chr(ord(i) ^ ord(j)) for i, j in zip(a, b))


def enc(x):
    y = lut[0][0]
    for i in range(10):
        y = xor(y, lut[i][ord(x[i])])
    return y


if enc(flag_content.decode('hex')).encode('hex') == target:
    print 'flag:'
    print 'flag{'+flag_content+'}'

'''
while True:
    print '01234567891123456789, send your payload'
    s = raw_input().strip()
    print enc(s.decode('hex')).encode('hex')
'''


def get_value_f(l, h):
    assert len(l) == 256
    return sum((1 & (l[i] >> h)) << i for i in range(256))


def apply(f, x):
    y = 0
    for i in range(256):
        if (f >> i) & 1 and (x & i) == i:
            y ^= 1
    return y


def to_value(f):
    return sum(apply(f, i) << i for i in range(256))


def b2i(s):
    return sum(j << (i*8)for i, j in enumerate(bytearray(s)))


def bitcnt(x):
    return bin(x).count('1')


def deg(f):
    v = 0
    for i in range(256):
        if 1 & (f >> i):
            v = max(v, bitcnt(i))
    return v


'''

vfs = [get_value_f(list(map(b2i, lut[0])), i) for i in range(80)]

afs = [to_value(i) for i in vfs]

for i in range(80):
    print '%2d %064x %064x %d' % (i, vfs[i], afs[i], deg(afs[i]))
'''
"""
