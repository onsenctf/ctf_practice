# My solution for Three-Time_Pad
## 概要
* [ワンタイムパッド](https://ja.wikipedia.org/wiki/%E3%83%AF%E3%83%B3%E3%82%BF%E3%82%A4%E3%83%A0%E3%83%91%E3%83%83%E3%83%89#)の鍵を3度使いまわしているところが脆弱性になっている。
* [c2](../given_files/c2) と [p2](../given_files/p2) から鍵を求めて [c3](../given_files/c3) を復号する。
* ソルバー：[solve.py](./solve.py)

## 解答
### 1. c2の16進数表現を出力する：
```
$ xxd -p c2 | tr -d '\n'
06e2f65a4c256d0ba8ada164cecd329cae436069f83476e91757e91bd4a4cce2c60a8f9aac8cb14210d55253cd787c0f6a
```

### 2. p2も16進数表現しワンタイムパッドの鍵を求める：
```python
from Crypto.Util.number import *
p2 = bytes_to_long(b'printed on flammable material so that spies could')
c2 = 0x06e2f65a4c256d0ba8ada164cecd329cae436069f83476e91757e91bd4a4cce2c60a8f9aac8cb14210d55253cd787c0f6a
key = p2^c2
```

### 3. c3の16進数表現の末尾にゼロを埋めて鍵長と同じ長さにし、復号結果を出力：
```python
c3 = 0x03f9ea574c267249b2b1ef5d91cd3c99904a3f75873871e94157df0fcbb5d1eab94f938600000000000000000000000000
print(long_to_bytes(c3^key))
```
少し解説しておく。ワンタイムパッドは、平文と鍵の最上位ビットから順に XOR を計算するアルゴリズムである。一方、python の`^`演算子は2つの被演算子の最下位ビットから順に XOR を計算するものである。最上位ビットから XOR が計算されるようにするためには、0 を末尾にパディングして c3 の桁を key の桁に揃える必要がある。

### 4. 実行する
```console
$ python3 solve.py
b'uiuctf{burn_3ach_k3y_aft3r_us1ng_1t}\xd8\xac\xc22y\xb0!s\xae\x17\tc\x0e'
```
