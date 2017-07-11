#!/usr/bin/python -i

INVALID = 'INVALID'

cache = [None] * (1 << 15)

for i in range(15):
    cache[(1 << i)] = ''

cache[0] = ''

pos = 'abcdefghijklmno'

delim = '\n'  #'\xff'


def solve(i):
    if cache[i] is not None:
        return cache[i]
    sol = INVALID
    for j in range(15):
        if not (i & (1 << j)):
            continue
        for k in range(6):
            j1 = jmp(j, k)
            j2 = jmp(j1, k)
            if j2 == -1:
                continue
            if (i & (1 << j1)) and not (i & (1 << j2)):
                par_sol = solve(i ^ (1 << j) ^ (1 << j1) ^ (1 << j2))
                if par_sol != INVALID:
                    sol = pos[j].upper() + pos[j2] + delim + par_sol
                    break
        if sol != INVALID:
            break
        #
    cache[i] = sol
    return sol


coord = [
    (0, 0),
    (0, 1),
    (1, 1),
    (0, 2),
    (1, 2),
    (2, 2),
    (0, 3),
    (1, 3),
    (2, 3),
    (3, 3),
    (0, 4),
    (1, 4),
    (2, 4),
    (3, 4),
    (4, 4),
]

dirs = [
    (-1, -1),
    (0, -1),
    (-1, 0),
    (1, 0),
    (0, 1),
    (1, 1),
]


def jmp(i, d):
    #  0 1
    # 2 i 3
    #  4 5
    if i == -1:
        return -1
    else:
        (x, y) = coord[i]
        (dx, dy) = dirs[d]
        if (x + dx, y + dy) in coord:
            return coord.index((x + dx, y + dy))
        return -1


"""
games = [
    0b111111111111110,
    0b111111111111101,
]
"""
games = [0b111111111111111 ^ (1 << i) for i in range(15)]
print ''.join([solve(i) for i in games])
