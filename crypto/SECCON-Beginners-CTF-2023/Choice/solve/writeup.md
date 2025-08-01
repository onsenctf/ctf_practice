# My solution for Choice

multi-prime RSA 系の問題。

素数 $p$ $q$ $r$ が不明で $n = pqr$ , $s = pq + qr + rp$ が与えられており、 $x_a = p^a + q^a + r^a$ ( $a$ は $n$ より大きい任意の数) をサーバーから何度でも入手できるようになっている。

まず、何度でも入手できる $p^a + q^a + r^a$ という式に着目するのがよさそうである。
そこで 「 $p^{a+1} + q^{a+1} + r^{a+1}$ が $p^a + q^a + r^a$ を用いて表せたりしないだろうか？」という発想に基づき $(p^a + q^a + r^a)(p + q + r)$ という式を考えてみると、以下のような等式が成り立つことが分かる：

$(p^a + q^a + r^a)(p + q + r) = s(p^{a-1} + q^{a-1} + r^{a-1}) - n(p^{a-2} + q^{a-2} + r^{a-2}) + p^{a+1} + q^{a+1} + r^{a+1}$

これより、サーバーから取得できる値のみを用いて $p + q + r$ が求められることが分かる。あとは $\phi$ および $d$ を求めれば暗号文が復号できる：

`solve.py`

```python3
from pwn import *
from crypto import *

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

print(N(pow(c,d,n)).bytes())
```

`ctf4b{E4sy_s7mmetr1c_polyn0mial}`


