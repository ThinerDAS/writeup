with open('enc','r') as f:
    u,c=eval(f.read())

with open('pubkey','r') as f:
    g,h,z=eval(f.read())

P = 173679354585523418477187462024504455998034329173335339952282476171310698849633901515173353474480211201
F = GF(P)
N = 35

def MatF(l):
    return matrix([[F(i) for i in row] for row in l])

U=MatF(u)
C=MatF(c)
G=MatF(g)
H=MatF(h)
Z=MatF(z)

T=(G*Z-Z*G)

ev=kernel(T).basis()[0]

g=((G.transpose()*ev)[0])/(ev[0])
h=((H.transpose()*ev)[0])/(ev[0])
z=((Z.transpose()*ev)[0])/(ev[0])
u=((U.transpose()*ev)[0])/(ev[0])
c=((C.transpose()*ev)[0])/(ev[0])

# h=g^x
# u=g^y
# c=(m+z)*g^(x*y)


print 'g =',g
print 'h =',h
print 'z =',z
print 'u =',u
print 'c =',c
print 'P =',P

print 'znlog(Mod(kH,P),Mod(kG,P))'

# x=h.log(g)

x=131426230370998706684707180455307948782769587060042913899926112173267357048112721116886754336478065989

m=c/(u^x)-z

print 'm =',m
