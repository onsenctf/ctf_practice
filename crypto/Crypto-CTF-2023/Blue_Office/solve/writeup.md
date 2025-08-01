# My solution for Blue_Office
## 概要
* 擬似乱数生成器が暗号学的に安全でないところと、平文 (=フラグ) の先頭4文字が分かっていることが脆弱性になっている。
* [output.txt](../given_files/output.txt) から、連続する4つのシード値の部分ビットを割り出すことで、初期シードを計算しフラグを得る。
* ソルバー：[solve.py](./solve.py)

## 解答
### 1. [blue_office.py](../given_files/blue_office.py) を理解する
`blue_office.py`:
```python {.line-number}

#!/usr/bin/enc python3

import binascii
from secret import seed, flag

def gen_seed(s):
	i, j, k = 0, len(s), 0
	while i < j:
		k = k + ord(s[i])
		i += 1
	i = 0
	while i < j:
		if (i % 2) != 0:
			k = k - (ord(s[i]) * (j - i + 1))            
		else:
			k = k + (ord(s[i]) * (j - i + 1))
	
		k = k % 2147483647
		i += 1

	k = (k * j) % 2147483647
	return k

def reseed(s):
	return s * 214013 + 2531011

def encrypt(s, msg):
	assert s <= 2**32
	c, d = 0, s
	enc, l = b'', len(msg)
	while c < l:
		d = reseed(d)
		enc += (msg[c] ^ ((d >> 16) & 0xff)).to_bytes(1, 'big')
		c += 1
	return enc

enc = encrypt(seed, flag)
print(f'enc = {binascii.hexlify(enc)}')
```

まず flag で grep すると、  encrypt 関数で flag が暗号化され、その結果が [output.txt](../given_files/output.txt) に表示されていることが分かる。

`output.txt`:
```console
enc = b'b0cb631639f8a5ab20ff7385926383f89a71bbc4ed2d57142e05f39d434fce'
```

では encrypt 関数の挙動を見ていく。この関数は、 flag の一文字ずつに対し、reseed 関数で生成した `d` という擬似乱数の下から 3 バイト目の値を xor している。 (`d >> 16` で 2 バイト右シフトし、 `& 0xff` で 3 バイト目を抽出している。)
また、暗号化の際に単に xor の計算しか行っていないということは、暗号文を入力として同じ `d` を用いて encrypt 関数を呼び出すだけで、平文 (=フラグ) を求めることができる。つまり暗号化に使われた `d` を全て求めればフラグが得られる。

さて、 `d` の生成に使われる reseed 関数の挙動を見ていく。 
reseed は、初期シードを初期入力とし、以降前回の出力を次の入力としていくような類いの擬似乱数生成器になっている。
この手の擬似乱数生成器はほぼ脆弱と考えてよいので、これをクラックしていくことになる。

### 2. [output.txt](../given_files/output.txt) の値から `d` の下から 3 バイト目を逆算する。
フラグは `CCTF` から始まる。
この情報と output.txt に書かれている暗号文を使えば、連続する 4 つのシード値それぞれの下から 3 バイト目を、以下のように逆算することができる:
```console
$ python3
>>> enc = 0xb0cb631639f8a5ab20ff7385926383f89a71bbc4ed2d57142e05f39d434fce
>>> hex(0xb0 ^ ord('C'))
'0xf3'
>>> hex(0xcb ^ ord('C'))
'0x88'
>>> hex(0x63 ^ ord('T'))
'0x37'
>>> hex(0x16 ^ ord('F'))
'0x50'
```

初期シードを `seed` と呼び、 あるバイト列の下から 3 バイト目を抽出する関数を `cut` と呼ぶとすると、上記の値たちには以下のような関係が成り立つ：
```console
0xf3 == cut(reseed(seed))
0x88 == cut(reseed(reseed(seed)))
0x37 == cut(reseed(reseed(reseed(seed))))
0x50 == cut(reseed(reseed(reseed(reseed(seed)))))
```

このような式を満たす初期値 `seed` を全数探索する (これは現実的な時間で終わる) ：
```python
# cut lower 3rd byte 
def cut(s):
    return hex(s)[-6:-4]

# search
i = 0
while not ('f3' == cut(reseed(i)) and \
           '88' == cut(reseed(reseed(i))) and \
           '37' == cut(reseed(reseed(reseed(i)))) and \
           '50' == cut(reseed(reseed(reseed(reseed(i)))))):
    i += 1
```

### 3. encrypt を使って復号する
前述の通り、 xor をしているだけなので encrypt 関数をそのまま復号に使うことができる：
```python
seed = i
enc = 0xb0cb631639f8a5ab20ff7385926383f89a71bbc4ed2d57142e05f39d434fce

from Crypto.Util.number import *
print(encrypt(seed, long_to_bytes(enc)).decode())
```

```console
$ python3 solve.py
CCTF{__B4ck_0r!F1c3__C1pHeR_!!}
```
