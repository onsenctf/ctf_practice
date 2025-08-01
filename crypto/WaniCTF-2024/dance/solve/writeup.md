# My solution for dance

独自共通鍵暗号系の問題なので基本的には愚直に復号プログラムを書けばフラグが求まる。
ただし本問では共通鍵がハッシュ化されており、そのハッシュ値の元となる平文は一部秘匿されているため探索が必要となる。

暗号方式は以下のようになっている：

```python
    def encrypt(self, plaintext: bytes) -> bytes:
        encrypted_message = bytearray(0)

        for i in range(len(plaintext)//64):
            key_stream = self.__get_key_stream(self.key, self.counter + i, self.nonce)
            encrypted_message += self.__xor(plaintext[i*64:(i+1)*64], key_stream)

        if len(plaintext) % 64 != 0:
            key_stream = self.__get_key_stream(self.key, self.counter + len(plaintext)//64, self.nonce)
            encrypted_message += self.__xor(plaintext[(len(plaintext)//64)*64:], key_stream[:len(plaintext) % 64])

        return bytes(encrypted_message)
```

`__get_key_stream` で取得した 64 バイトの鍵を用いて 64 バイトずつ XOR によって暗号化する方式となっている。
XOR は暗号化プログラムと復号プログラムが完全に一致するので、本質的には平文を探索するだけの問題であることが分かる。

`solve.py`

```python
from Crypto.Util.number import *
from itertools import product

from chall import *
from mycipher import *


for minutes, sec, r in product(range(61), range(61), range(11)):
    username = 'gureisya'
    data1 = f'user: {username}, {minutes}:{sec}'
    data2 = f'{username}'+str(r)
    token = make_token(data1, data2)
    sha256 = hashlib.sha256()
    sha256.update(token.encode())
    key = sha256.hexdigest()[:32]
    nonce = token[:12]

    m = MyCipher(key.encode(), nonce.encode()).encrypt(long_to_bytes(int('061ff06da6fbf8efcd2ca0c1d3b236aede3f5d4b6e8ea24179',16)))
    if b'FLAG' in m:
        print(m)
        break

# => b'FLAG{d4nc3_l0b0t_d4nc3!!}' 
```

誤字で探索時間が無駄になるのが怖かったので、 `key` と `nonce` の生成部分は `chall.py` から拝借した。
