# My solution for Group_Projection

## 概要
*  $p-1$ の約数をサニタイズしていないところが脆弱性になっている
*  $k$ として $\frac{p-1}{d}$ ( $d$ は小さい整数) を選べば、ごく小さい探索回数でフラグが得られる
* ソルバー：[solve.py](./solve.py)

## 解答
### 1. [chal.py](../given_files/chal.py) を理解する
本問は[Group Project](../../Group_Project/README.md) に類似している。
Gropu Project では $k = 0$ がサニタイズされていなかったので $g^{abk} = g^{0} = 1$ と簡単に $S$ の値を計算出来たが、今回はそう簡単には計算できないことが分かる。

### 2. $k$ の値を工夫して $g^{abk}$ を現実的な時間で探索できるようにする
例えば素数 $p$ を $101$ とし、 秘密 $S = g^{abk}\ \text{mod}\ p$ を作ったとする。
このとき $k$ として $p - 1 = 100$ の (比較的大きい) 約数である $25$ を選んだとすると、 $S = g^{25 \cdot ab}\ \text{mod}\ p$ となる。
さて、フェルマーの小定理により $g^{p-1}\ \text{mod}\ p = 1$ が成立するので、 $g^{25 \cdot ab}$  の値は $g^{25 \cdot i}$ (ただし $i$ は $1$ から $(p-1) / 25 = 4$) の4通りしか取り得ないことになる。

つまり、 $k$ として $p-1$ の比較的大きい約数を選ぶことで、 $g^{abk}$ の取り得る値のパターンを絞り込むことができるのである。 このような攻撃手法は [Small subgroup confinement attack](https://crypto.stackexchange.com/questions/27584/small-subgroup-confinement-attack-on-diffie-hellman) (小さい部分群に閉じ込める攻撃？) と呼ばれている。 なお、先ほどから **比較的大きい約数** などと回りくどい言い方をしているのは、1番目と2番目に大きい約数である $p-1$ と $\frac{p-1}{2}$ がサニタイズされているからである。

さて、これをコードとして記述すると以下のようになる：
```python
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
```

あとは実行するだけである。
```console
$ python3 solve.py
```

