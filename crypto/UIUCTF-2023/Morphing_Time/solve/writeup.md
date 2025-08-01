# My solution for Morphing_Time

## 概要
* 復号オラクルが与えられているところが脆弱性になっている。
* `c1_` として `g` を、`c2_` として `A` を送ることでフラグが得られる。
* ソルバー：[solve.py](./solve.py)

## 解答
### 1. chal.py を理解する
[chal.py](../given_files/chal.py) を `flag` で grep すると、`flag` は encrypt 関数によって暗号化されていることが分かる。
encrypt は、平文 $m$ を入力とし (素数 $p$ を法とする世界で) $c_1 = g^{k}$ と $c_2 = g^{ak} \cdot m$ とを返す関数である。

66行目からの処理により、プレイヤーは入力 $\bar{c_1}$ , $\bar{c_2}$ をサーバーに送信できる。サーバーはこの $\bar{c_1}$ , $\bar{c_2}$ と、暗号文 $c_1$ , $c_2$ を用いて (素数 $p$ を法とする世界で) $\textsf{decrypt}(c_1 \cdot \bar{c_1}, c_2 \cdot \bar{c_2}$) という復号結果を漏洩してしまっている。

なお、 $\textsf{decrypt}(c_1 \cdot \bar{c_1}, c_2 \cdot \bar{c_2})$ は、
$m = \frac{c_2 \cdot \bar{c_2}}{(c_1 \cdot \bar{c_1})^a}$
を返す。

### 2. 入力 $\bar{c_1}, \bar{c_2}$ を工夫して $c_1, c_2$ を復号させる。
`flag` を暗号化した結果は $c_1, c_2$ に格納されているのだから、これを復号(つまり $\frac{c_2}{c_1^a}$ の値を計算) できれば勝ちということになる。 ここで、 $\bar{c_1}, \bar{c_2}$ をうまく選ぶと、$`m = \frac{c_2 \cdot \bar{c_2}}{(c_1 \cdot \bar{c_1})^a} = \frac{c_2}{c_1^a}`$ という等式を成立させることができる。

サーバーが公開している値 `g`, `p`, `A` ( `== g^a` ), `c1`, `c2` のうち、 $\bar{c_1}$ として `g` を、 $\bar{c_2}$ として `A` を選べば
$\frac{c_2 \cdot \bar{c_2}}{(c_1 \cdot \bar{c_1})^a} = \frac{c_2 \cdot g^a}{(c_1 \cdot g)^a} = \frac{c_2}{c_1^a}$ が成立する。

### 3. プログラムを書いて実行
```python
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
m = io.recvline().strip()

io.close()

from Crypto.Util.number import *
print(long_to_bytes(int(m)).decode())
```

```console
$ python3 solve.py
uiuctf{h0m0m0rpi5sms_ar3_v3ry_fun!!11!!11!!}
```
