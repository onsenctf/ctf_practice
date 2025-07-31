from Crypto.Util.number import *
from pwn import *

r = remote('01-translator.challenges.beginners.seccon.jp', 9999)
r.sendline(b'0' * 16)
r.sendline(b'1' * 16)
r.recvuntil(b'ct: ')
ct = r.recvline().decode().strip()
one = ct[32*1:32*2]
zero = ct[32*2:32*3]
print(long_to_bytes(int(ct.replace(one, '1').replace(zero, '0')[:-32], 2)).decode())
