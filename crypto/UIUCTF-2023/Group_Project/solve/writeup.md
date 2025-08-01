# My solution for Group_Project

## 概要
* AESをECBモードで使用しているところと `k` の入力に対する例外処理が甘いところが脆弱性になっている。
* `k` として `0` を代入することにより、ECBモードの鍵が手元で再現できるようになるので `c` が復号できる。
* ソルバー：[solve.py](solve.py)

## 解答
### 1. chal.py の脆弱性を見つける
36, 37行目を見ると、 `flag` は AES で暗号化されており、暗号化鍵には `S` という変数の md5 ハッシュ値が使われていることが分かる。 そして 14～34行目を見ると、この `S` は $g^{abk}\ \text{mod}\ p$ の形で与えられる数値となっていることが分かる。 ここで `a`, `b` はサーバ側で定まる値、 `k` はプレイヤーが入力する値である。

$g^{abk}\ \text{mod}\ p$ という値は（[CDH仮定](https://qiita.com/visvirial/items/09f0adc531b0d13ad931)により） $g^{ab}$ が与えられない限り手元で計算することが困難なため、一般的には、 `k` をプレイヤーが指定できるからと言って秘密鍵 `S` までは求められない。つまり、プレイヤーは自分の意志で秘密鍵を選ぶことはできないということである。ところが今回は `k` が 0 の場合を例外として扱っていないため、 `S == g^(k*a*b) == g^(0*a*b) == 1` としてプレイヤーが秘密鍵を選べてしまう。あとはこの鍵を用いて AES で復号すればよい。

### 2. S を 1 として暗号文を復号する
```python
from Crypto.Cipher import AES
from Crypto.Util.number import *
from hashlib import *

c = 31383420538805400549021388790532797474095834602121474716358265812491198185235485912863164473747446452579209175051706
cipher = AES.new(md5(long_to_bytes(1)).digest(), AES.MODE_ECB)
print(cipher.decrypt(long_to_bytes(c)).decode())
```

```console
$ python3 solve.py
uiuctf{brut3f0rc3_a1n't_s0_b4d_aft3r_all!!11!!}
```
