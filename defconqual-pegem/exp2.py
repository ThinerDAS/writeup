#!/usr/bin/python -i

with open('pegem', 'rb') as f:
    raw_bin = f.read()

with open('sol', 'rb') as f:
    sol = f.read()

overflow_buf = '1' * (0x1d5 - 0xb2)
#for i in range(2,50):
#    overflow_buf+=chr(i)+'\xff\x00'

#overflow_buf=overflow_buf.ljust(294-1)

overflow_buf += chr(0x22)
overflow_buf += chr(0xff)
overflow_buf += chr(0xb2)


def hostile(i):
    return sol + '1' * (0x1d5 - 0xb2) + chr(i) + chr(0xff) + chr(0x0a)

print hostile(0x20)

raw_mem = raw_bin[0x1020:0x11020]

orig_mem = []

for i in range(0x8000):
    orig_mem.append(int(raw_mem[i * 2:(i + 1) * 2][::-1].encode('hex'), 16))

mem = []
ip = 0
buf = ''


def reset():
    global mem
    global ip
    global buf
    mem = [i for i in orig_mem]
    ip = 0
    buf = ''


reset()


def strings(n=3):
    global mem
    begin_index = 0
    for i in range(0x8000):
        visible = mem[i] >= 0x20 and mem[i] < 0x7f
        if not visible or i == 0x7fff:
            # stop
            if i - begin_index > n:
                print '%04x: "%s"' % (begin_index, ''.join(
                    [chr(j) for j in mem[begin_index:i]]))
            begin_index = i + 1


def le(i):
    return i <= 0 or i >= 0x8000


def poly_sub(a, b):
    term_related = list(set([j for i, j in a + b]))
    c = []
    for t in term_related:
        at = [i for i in a if i[1] == t]
        bt = [i for i in b if i[1] == t]
        ai = 0 if not at else at[0][0]
        bi = 0 if not bt else bt[0][0]
        ci = ai - bi
        c.append((ci, t))
    return [i for i in c if i[0]]


def decompile(ip):
    # return (pp, [ip set that may occur afterwards])
    A = mem[ip]
    B = mem[ip + 1]
    C = mem[ip + 2]
    r = ppl(ip, A, B, C)
    modrefered = []
    if C != ip + 3:
        ipset = [C, ip + 3]
        for i in range(ip, ip + 3):
            if mem[i] != orig_mem[i]:
                modrefered.append(mem[i])
    else:
        # add here chained eval
        """
        A2 = mem[ip + 3]
        B2 = mem[ip + 4]
        C2 = mem[ip + 5]

        if C2 == C + 3 and A == B and B2 == B:
            r = '%04x: \x1b[33m[%04x] = -[%04x]\x1b[m' % (C, B, A2)
            if A2 == 0xffff:
                r = '%04x: \x1b[33m[%04x] = \x1b[1mgetchar()\x1b[m' % (C, B)

            ipset = [C2]
            pass
        else:
        """
        # assignments := [[left_val,[(k,right_vali),...]],...]
        ases = dict()
        t_i = ip
        C_i = mem[t_i + 2]
        comment = ''
        while C_i == t_i + 3 and C_i < 0x7fff:
            A_i = mem[t_i]
            B_i = mem[t_i + 1]
            if B_i in ases:
                old_Bv = ases[B_i]
            else:
                old_Bv = [(1, B_i)]
            if A_i in ases:
                old_Av = ases[A_i]
            else:
                old_Av = [(-1 if A_i == 0xffff else 1, A_i)]
            if B_i == 0xffff:
                ases[B_i] = old_Av
            else:
                ases[B_i] = poly_sub(old_Bv, old_Av)
            t_i += 3
            C_i = mem[t_i + 2]
            if t_i in ases or t_i + 1 in ases or t_i + 2 in ases:
                # self_modifying code
                comment += '\x1b[33m<self modifying code detected>\x1b[m\n'
                break
        r = '\n'.join(
            [('\x1b[32;1m' if P == 0xffff else
              ('\x1b[33;1m'
               if len([i for i in ases[P] if i[1] == 0xffff]) else '')) +
             ('[%04x] = ' % P) +
             (' + '.join(['(%d[%04x])' % i for i in ases[P] if i[0]]) +
              (' = %04x' %
               (sum([i[0] * mem[i[1]] for i in ases[P] if i[1] != 0xffff])
                % 0x10000)) if len(ases[P]) > 0 else '0') + '\x1b[m'
             for P in ases]) + '\n' + comment
        for i in range(ip, t_i):
            if mem[i] != orig_mem[i]:
                modrefered.append(mem[i])
        refered = sorted(
            list(set([j[1] for P in ases for j in ases[P] if j[1] != 0xffff])))
        r = ('%04x - %04x: ' % (ip, t_i)) + ', '.join(
            ['[%04x] = %04x' % (i, mem[i]) for i in refered]) + '\n' + r
        ipset = [t_i]
    for i in set(modrefered):
        r = r.replace('%04x' % i, ('\x1b[44m%04x\x1b[49m' % i))
    return (r, ipset)


def ppl(ip, A, B, C):
    plain = 'ip = %04x, A = %04x, B = %04x, C = %04x' % (ip, A, B, C)
    p = ''
    branch = (C != ip + 3)
    if A == 0xffff:
        # input
        p = '[%04x] = getc()' % B
        if branch:
            p += ', if getc()<=0: jmp %04x' % C
        p = '\x1b[33;1m' + p + '\x1b[m'
    elif B == 0xffff:
        p = '\x1b[32;1mputc([%04x])\x1b[m' % A
    else:
        if branch:
            if B == A:
                p = '\x1b[35;1m[%04x]=0; jmp %04x\x1b[m' % (B, C)
            else:
                p = '\x1b[36;1m(if [B=%04x] <= [A=%04x]: branch %04x)\x1b[m; [B] -= [A]' % (
                    B, A, C)
            pass
        else:
            if B == A:
                p = '[%04x] = 0' % (B)
            else:
                p = '[%04x] -= [%04x]' % (B, A)
    if (A > 3 and A < 0x38) or (B > 3 and B < 0x38) or (C > 3 and C < 0x38):
        p = '\x1b[41m' + p + '\x1b[m'
    p = ('%04x: ' % ip) + p
    return p


def instrument(inputs='', debug=False, quiet=False):
    global mem
    global ip
    global buf
    target_ipset = [ip]
    while True:
        if ip < 0 or ip >= 0x8000 - 2:
            print 'Access Violation by ip'
            return
        A = mem[ip]
        B = mem[ip + 1]
        C = mem[ip + 2]
        #print 'ip = %04x, A = %04x, B = %04x, C = %04x' % (ip, A, B, C)
        #print pp(ip, A, B, C)
        if ip in target_ipset and not quiet:
            pp, target_ipset = decompile(ip)
            print pp
            if debug:
                raw_input('continue ->')
        if A == 0xffff and B == 0xffff:
            print 'IO violation'
            return
        elif A == 0xffff:
            # getc
            c = None
            if len(inputs) > 0:
                c = ord(inputs[0])
                inputs = inputs[1:]
            else:
                while not isinstance(c, int):
                    if not quiet or len(inputs) == 0:
                        print '###### Buffer ######'
                        print buf
                        print '### Buffer  ends ###'
                    desc = raw_input('getchar() : ').rstrip('\n')
                    if len(desc) == 1:
                        c = ord(desc)
                    else:
                        c = eval(desc)
                    if isinstance(c, str):
                        if len(c) == 1:
                            c = ord(c)
                        else:
                            print 'String length should be 1'
                            c = None
                    elif isinstance(c, int):
                        c = c
                    else:
                        print c, 'is not a char candidate'
                        c = None
            c = c % 256
            if c > 0x7f:
                c = c - 256
            if not quiet:
                print '[B] =', c
            mem[B] = c % 0x10000
            if c <= 0:
                ip = C
            else:
                ip += 3
        elif B == 0xffff:
            # getc
            buf = (buf + chr(mem[A] % 256))[-256:]
            if not quiet:
                print '###### Buffer ######'
                print buf
                print '### Buffer  ends ###'
            ip += 3
            #raw_input('continue ->')
        else:
            mem[B] -= mem[A]
            mem[B] %= 0x10000
            if le(mem[B]):
                ip = C
            else:
                ip += 3
            #raw_input('continue ->')


ins = instrument
