# My solution for Suction

## 概要
* 以下の2点が脆弱性になっている：  
  *  128 ビットという小さい素数を鍵の生成に使ってしまっていること
  * 公開鍵と暗号文の末尾ビット列が秘匿されているものの、それらが 8 ビットと短すぎること
* $n$ を素因数分解し暗号文を復号する。 ただし、要所要所で 8 ビット分の探索を行う必要がある。
* ソルバー：[solve.py](./solve.py)

## 解答
### 1. [suction.py](../given_files/suction.py) を理解する
`suction.py`:
```python
#!/usr/bin/env python3

from Crypto.Util.number import *
from flag import flag

def keygen(nbit, r):
	while True:
		p, q = [getPrime(nbit) for _ in '__']
		e, n = getPrime(16), p * q
		phi = (p - 1) * (q - 1)
		if GCD(e, phi) == 1:
			N = bin(n)[2:-r]
			E = bin(e)[2:-r]
			PKEY = N + E
			pkey = (n, e)
			return PKEY, pkey

def encrypt(msg, pkey, r):
	m = bytes_to_long(msg)
	n, e = pkey
	c = pow(m, e, n)
	C = bin(c)[2:-r]
	return C

r, nbit = 8, 128
PKEY, pkey = keygen(nbit, r)
print(f'PKEY = {int(PKEY, 2)}')
FLAG = flag.lstrip(b'CCTF{').rstrip(b'}')
enc = encrypt(FLAG, pkey, r)
print(f'enc = {int(enc, 2)}')
```


flag で grep すると、`CCTF{` `}` の部分が剥ぎ取られたフラグが、 encrypt 関数によって暗号化され print されていることが分かる。
この print の内容は、 `PKEY` を print したものと合わせて [output.txt](../given_files/output.txt) に記述されている。


ではフラグの暗号化に用いられた encrypt 関数を見ていこう。
`c = pow(m, e, n)` までは普通の RSA 暗号の暗号化アルゴリズムなのだが、 `C = bin(c)[2:-r]` を返り値としている点が RSA 暗号とは異なる。
`bin(c[2:-r])` を分割して理解すると以下のような意味だと分かる：

  1. `bin(c)[2:]` は、 bin 関数の出力 `'0b....'` のうち、 `'0b'` の部分を剥ぎ取って二進数表記の部分だけを取得。
  2. `bin(c)[2:-r]` とすることで、さらにその出力の下位 r (= 8) ビットを剥ぎ取った文字列を取得。

つまり、 encrypt された暗号文のうち、下位 8 ビットは秘匿されているということである。


次に、 `PKEY` を生成するための keygen 関数を見ていこう。
ビット数が短いことを一旦気にしなければ、 `if GCD(e, phi) == 1:` までは RSA 暗号の鍵生成アルゴリズムなのだが、それ以降が RSA 暗号とは異なる。
まず 公開鍵 n, e の下位 8 ビットが、encrypt のときと同様に剥ぎ取られ、それぞれ N, E に代入されている。
そしてこのN, E を `PKEY` とし、元の n, e を `pkey` として返している。


### 2. N に対し 8 ビット分の探索を行うことで n を素因数分解する
まず一般的に、 RSA 暗号の公開鍵に使う素数として 128 ビットは短すぎるので、 [factordb](http://www.factordb.com/) などで簡単に素因数分解できてしまう。
今回は n の値そのものは分からず、 N という n の下位 8 ビット分の情報が無い値しか分からないという少し強い制限があるが、この場合でも同様である。
なぜなら、剥ぎ取られたビット分を総当たりしたとしても 2^8 = 128 回というごく小さい回数しかかからないからだ。

実際、 [factordb を python から呼び出す](https://github.com/ryosan-470/factordb-python) ことで N から n と n の素因数 p, q まで求められる：
```python
from factordb.factordb import *
PKEY = 55208723145458976481271800608918815438075571763947979755496510859604544396672
n = int(bin(PKEY)[2:-8] + '0'*8, 2)
for i in range(256):
    f = FactorDB(n+i)
    f.connect()
    factors = f.get_factor_list()
    if len(factors) == 2 and factors[0].bit_length() == factors[1].bit_length():
        print(factors)
        break
```
これを実行すると、`[188473222069998143349386719941755726311, 292926085409388790329114797826820624883]` という素因数が分かる (数分かかる) 。

### 3. E と C に対し 8 ビット分の探索を行うことでフラグを得る
n の素因数 p, q が分かったので、本質的には解けている。
あとは E と C に対しても、剥ぎ取られた 8 ビット分の探索を挟みながら RSA 暗号の復号を行えばよい：
```python
e = 0b1000000000000000
e_candidates = []
for i in range(2**8):
    if isPrime(e+i):
        e_candidates.append(e+i)

c = 0b100011111111101010101110111101011100100001110101010001111110000000100000011000000000000000111000100100101110010001010010001101011110101001110100100010000011011110110100011000100101000000111110000111100101110000011000100100001001101101011100010100100000000
for e_ in e_candidates:
    d_ = pow(e_, -1, (p-1)*(q-1))
    for i in range(2**8):
        s ="".join([chr(c) for c in long_to_bytes(pow(c+i,d_,p*q))])
        if s.isprintable():
            print('CCTF{'+s+'}')
```

まず e は素数であることを利用して探索範囲を少し削減している。
また、復号された候補が正しいかどうかの判定は、「印字可能文字のみからなるか」という条件で行った。
それが、 `s.isprintable()` の意味である。


あとはソルバーを実行すればフラグが得られる。
```console
$ python3 solve.py
CCTF{6oRYGy&Dc$G2ZS}
```

