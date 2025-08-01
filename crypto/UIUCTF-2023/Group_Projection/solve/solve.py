from Crypto.Util.number import *
from Crypto.Cipher import AES
from hashlib import *
from pwn import *

r = remote('localhost', 8000)

r.recvuntil(b'p = ')
p = int(r.recvline().strip())

d = 3
while (p-1) % d:
    d += 1
k = (p-1) // d

r.recvuntil(b'k = ')
r.sendline(str(k).encode())

r.recvuntil(b'c = ')
c = int(r.recvline().strip())

for i in range(d):
    cipher = AES.new(md5(long_to_bytes(pow(2,i*k,p))).digest(), AES.MODE_ECB)
    if b'uiuctf' in cipher.decrypt(long_to_bytes(c)):
        print(cipher.decrypt(long_to_bytes(c)))
