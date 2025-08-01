# My solution for Easy_calc

`A = f(s, p)` の計算を追うと $A = \sum_{i=1}^{p-1} i \cdot s^i\ \mathsf{mod}\ p$ であることが分かる。
数列の和を計算すると $\sum_{i=1}^{p-1} i \cdot S^i = \frac{s-p\cdot s^p + (p-1)\cdot s^{p+1}}{(1-s)^2}$ である。
また $p$ は素数なので $\mathsf{mod}\ p$ の下で $s^{p+1}$ は $s^2$ である。 
よって $A = \frac{s}{1-s}$ が言える。 
ゆえに $s = \frac{A}{1+A}$ から AES の暗号化に使用された鍵が割り出せるのでフラグが求まる。

`solve.py`

```python
from hashlib import md5
from Crypto.Cipher import AES
from Crypto.Util.number import *

exec(open('output.txt').read())

s = (A * pow(1+A, -1, p)) % p
print(AES.new(md5(long_to_bytes(s)).digest(), AES.MODE_CBC, iv=int(ciphertext[:32],16).to_bytes(16,'big')).decrypt(int(ciphertext[32:], 16).to_bytes(32, 'big')))

# => b'FLAG{Do_the_math396691ba7d7270a}'
```
