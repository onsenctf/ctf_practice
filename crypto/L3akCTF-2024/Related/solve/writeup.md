# My solution for Related

`flag` と線形の関係にある 2 種の平文 `a1*flag + b1` と `a2*flag + b2` の暗号文が与えられている。
よって [Franklin-Reiter Related Message Attack](https://hackmd.io/@Xornet/B16W75IND) を用いると `flag` が求まる。

[`solve.sage`](./solve.sage)

```sage
from Crypto.Util.number import *

# load n, a1, b1, ct1, a2, b2, ct2, e
# ...

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a.monic()
    
R.<x> = Zmod(n)[]

f = (a1*x + b1)^e - ct1
g = (a2*x + b2)^e - ct2

m = -gcd(f, g).coefficients()[0]

print(long_to_bytes(int(m)))
```
