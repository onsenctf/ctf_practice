from pwn import *; context.log_level = 'WARNING'

host, port = 'morphing.chal.uiuc.tf', 1337
io = remote(host, port)

io.recvuntil(b'g = ')
g = io.recvline().strip()

io.recvuntil(b'A = ')
A = io.recvline().strip()

io.recvuntil(b'c1_ = ')
io.sendline(g)

io.recvuntil(b'c2_ = ')
io.sendline(A)

io.recvuntil(b'm = ')
m = int(io.recvline().strip())

io.close()

from Crypto.Util.number import *
print(long_to_bytes(int(m)).decode())
