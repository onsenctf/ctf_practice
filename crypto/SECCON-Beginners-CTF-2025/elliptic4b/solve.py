from pwn import remote
from sage.all_cmdline import *

p = 2**256 - 2**32 - 977
F = GF(p)
E = EllipticCurve(F, [0, 7])
X = PolynomialRing(F, 'X').gen()

r = remote('elliptic4b.challenges.beginners.seccon.jp', 9999)
r.recvuntil(b'y = ')
y = int(r.recvline().decode())

x = (X**3 - y**2 + 7).roots()[0][0]
a = E.point((x, y)).order() - 1

r.sendline(str(int(x)).encode())
r.sendline(str(int(a)).encode())

print(r.recvall().decode())
