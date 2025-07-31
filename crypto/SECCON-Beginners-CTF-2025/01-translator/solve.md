# 01-translator.py

## 脆弱性

AESのECBモードを利用している点

## 解答

01-translator.py の 13-17行目を見ると、サーバが応答する暗号文は、2進数化されたフラグのビット値 `0` `1` のそれぞれを、ユーザの入力 `trans_0` `trans_1` に置換し、それを AES-ECB で暗号化したものであることが分かる :

```py
trans_0 = input("translations for 0> ")
trans_1 = input("translations for 1> ")
flag_translated = flag_bin.translate(str.maketrans({"0": trans_0, "1": trans_1}))
key = os.urandom(16)
print("ct:", encrypt(flag_translated, key).hex())
```

AES ECB による1回の暗号化において、同一の平文は、それが何番目のブロックかによらず、必ず同一の暗号文になる。よって `trans_0` `trans_1` のそれぞれに、長さがブロック長と等しく互いに異なる適当な値を割り当てればよい。なぜなら、これによりサーバの応答の各ブロックが `0` または `1` に対応するからである（ただし末尾ブロックは PKCS \#7 パディングブロック `\x10 * 16` に対応する）。

またフラグの先頭文字は `c` = `0b1100011` と既知なので、応答の2ブロック目と3ブロック目がそれぞれ `1` と `0` に対応することがわかる。以上のことから以下のようなソルバを実行しフラグを得る :

```py
from Crypto.Util.number import *
from pwn import *

r = remote('01-translator.challenges.beginners.seccon.jp', 9999)
r.sendline(b'0' * 16)
r.sendline(b'1' * 16)
r.recvuntil(b'ct: ')
ct = r.recvline().decode().strip()
one = ct[32*1:32*2]
zero = ct[32*2:32*3]
print(long_to_bytes(int(ct.replace(one, '1').replace(zero, '0')[:-32], 2)))
```

```
ctf4b{n0w_y0u'r3_4_b1n4r13n}
```
