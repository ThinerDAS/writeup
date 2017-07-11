equ = [
    0x00000000146fc26a,
    0x0000000010766b04,
    0x000000002ae5ce6c,
    0x000000002df5fce4,
    0x000000002434019a,
    0x000000001f67e99d,
    0x000000004048aa7f,
    0x000000004c26c74c,
    0x0000000016b2964e,
    0x0000000013905802,
    0x0000000033cf9b5f,
    0x000000002cd5980f,
    0x000000001dfcc164,
    0x0000000014a99da3,
    0x000000002c101662,
    0x000000002ba9dedb,
]

k = [
    0x0000000000001380, 0x00000000000025fa, 0x0000000000000caa,
    0x00000000000000e2, 0x00000000000004e4, 0x00000000000056da,
    0x0000000000001a61, 0x000000000000123f, 0x0000000000002709,
    0x0000000000000103, 0x0000000000000e07, 0x00000000000000c0,
    0x0000000000002035, 0x0000000000001531, 0x0000000000000020,
    0x0000000000000dc7
]

mat=Matrix(QQ,4,4,k)

matinv=mat^(-1)

vl=[]

for i in range(4):
    v=vector([equ[j*4+i] for j in range(4)])
    vo=matinv*v
    vl.append(vo)

for i in range(4):
    for j in range(4):
        print vl[j][i]

