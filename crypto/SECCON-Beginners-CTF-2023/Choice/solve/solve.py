from pwn import *
from sage.all import *
from Crypto.Util.number import *

r = remote('localhost', 1336)
r.recvuntil(b'n = '); n = int(r.recvline())
r.recvuntil(b'e = '); e = int(r.recvline())
r.recvuntil(b'c = '); c = int(r.recvline())
r.recvuntil(b's = '); s = int(r.recvline())

a = n + 3

r.sendlineafter(b'input a(a>n) : ', str(a).encode())
r.recvuntil(b'result_a : '); res_a = int(r.recvline())

r.sendlineafter(b'input a(a>n) : ', str(a-1).encode())
r.recvuntil(b'result_a : '); res_a_sub_1 = int(r.recvline())

r.sendlineafter(b'input a(a>n) : ', str(a-2).encode())
r.recvuntil(b'result_a : '); res_a_sub_2 = int(r.recvline())

r.sendlineafter(b'input a(a>n) : ', str(a+1).encode())
r.recvuntil(b'result_a : '); res_a_add_1 = int(r.recvline())

p_q_r = ((s*res_a_sub_1 - n*res_a_sub_2 + res_a_add_1) * pow(res_a, -1, n)) % n

phi = n + p_q_r - s - 1
d = pow(e, -1, phi)

print(long_to_bytes(pow(c,d,n)))
