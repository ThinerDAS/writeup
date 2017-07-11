#!/usr/local/bin/ipython -i

pre4flag = [
    33886, 22552, 63741, 55411, 14063, 7267, 20053, 33082, 8501, 26295, 61677,
    51450, 41721, 34152, 29188, 26814
]

rand_longlong = [0] * 4

for i in range(4):
    rand_longlong[i] = (pre4flag[i * 4] << 48) + (
        pre4flag[i * 4 + 1] << 32) + (pre4flag[i * 4 + 2] << 16) + (
            pre4flag[i * 4 + 3])
print rand_longlong
seed34 = [0x880f0e3a, 0x16d856af, 0x058ff310, 0xd8e8367c]

seed3 = seed34[0] + (seed34[1] << 32)
seed4 = seed34[2] + (seed34[3] << 32)


def rot(l, b):
    # right being positive
    return ((l >> b) | (l << (64 - b))) % (2**64)


def reverse_machine(v1, v2, v3, v4):
    # return original v1,v2
    vv3 = v3
    vv4 = v4
    v4l = []
    for i in range(0x20):
        v4l.append(vv4)
        vv3 = rot(vv3, 8)
        vv3 = (vv3 + vv4) % (2**64)
        vv3 ^= i
        vv4 = rot(vv4, 64 - 3)
        vv4 ^= vv3

    vv1 = v1
    vv2 = v2
    #vv2 ^= vv1

    for i in range(0x20 - 1, -1, -1):
        vv2 ^= vv1
        vv2 = rot(vv2, 3)
        vv1 ^= v4l[i]
        vv1 = (vv1 - vv2) % (2**64)
        vv1 = rot(vv1, 64 - 8)

    return vv1, vv2


v11, v12 = reverse_machine(rand_longlong[0], rand_longlong[1], seed3, seed4)
v21, v22 = reverse_machine(rand_longlong[2], rand_longlong[3], seed3, seed4)

vvv = [v11, v12, v21, v22]
vvval = []
for i in range(4):
    vvval.append((vvv[i] >> 48) % 65536)
    vvval.append((vvv[i] >> 32) % 65536)
    vvval.append((vvv[i] >> 16) % 65536)
    vvval.append((vvv[i]) % 65536)

xornode = []

for i in [
        0x70bc90df, 0x5a96ef57, 0x5509cfee, 0x0d2080ce, 0x070ee14f, 0x2fc6a446,
        0x5355ecf0, 0x6457782b
]:

    xornode.append((i) % 65536)
    xornode.append((i >> 16) % 65536)

print ''.join([chr(xornode[i] ^ vvval[i]) for i in range(16)])
