# My solution for Really_Simple_Algorithm

[`server.py`](../given_files/server.py) を見ると、同一の平文 m を、異なる n で暗号化した暗号文を何種類でも取得できることが分かる。
よって [Hastad Broadcast Attack](https://www.ochappa.net/posts/rsa-hba) を用いて e 種類の暗号文から 平文 m を求めればよい。

[`solve.py`](./solve.py)

```python
from Crypto.Util.number import *
from gmpy2 import *
from pwn import *
from sympy.ntheory.modular import *

r = remote('193.148.168.30', 5668)

ns = []
cs = []
for i in range(1337):
    print(i)
    r.sendlineafter(b'Select Option: ', b'2')
    r.recvuntil(b'n = ')
    ns.append(int(r.recvline().decode()))
    r.recvuntil(b'flag = ')
    cs.append(int(r.recvline().decode()))
r.sendlineafter(b'Select Option: ', b'3')

print(long_to_bytes(iroot(crt(ns, cs)[0], 1337)[0]))

# => L3AK{H4sTAD5_bR0aDc45T_4TtacK_1s_pr3tTy_c0ol!}
```
