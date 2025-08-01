# My solution for reiwa_rot13

## `chall.py` について

まず、フラグは AES ECB で暗号化されている。
また、この AES の暗号化鍵は、10バイトのランダム文字列 `key` の SHA256 ハッシュ値となっている。

AES は共通鍵暗号方式なので、このランダム文字列 `key` が分かればフラグが求まる。

ランダム文字列 `key` にまつわる情報として、以下の二つが与えられている：

* `c1` : `key` をRSA で暗号化した暗号文。
* `c2` : `key` をROT13 で暗号化した文字列をRSAで暗号化した暗号文。

これらの情報から `key` を求め、フラグを復号する。

## 解説

2種の平文 `key` と `rot13_key` の間には、ある整数 `r` を用いて

```
rot13_key == key + r
```

という関係が成り立っている。
この `r` は、「文字列を ROT13 する際に加えられる整数」を意味する。

`r` の具体例を2つ挙げる。
例えば文字列 `abc` を ROT13 するとは、`r = (13 * 0x100**2) + (13 * 0x100**1) + (13 * 0x100**0)`
を `abc` に加えるということである。
また、 `az` を ROT13 するなら `r = (13 * 0x100*1) + ((-13) * 0x100**0)` を `az`
に加えるということになる (z の13個 **次** のアルファベットは m 、つまり 13 個 **前** のアルファベットになるため) 。

今回の場合において `r` が具体的にどの値かは、1024通りの探索の余地がある
(`[13, -13]` から重複を許し10個選ぶ選び方)。
1024通りであれば現実的な時間で攻撃が完了することが予測できる。

`r` の候補は以下のように取得できる：

```sage
rs = []
for rots in itertools.product([13, -13], repeat=KEY_LEN):
    rs.append(sum(map(operator.mul, [256 ** i for i in range(KEY_LEN)], rots)))
```

さて、 `key` と `rot13_key` との間に `rot13_key == key + r`
という関係があるときに使えるのが **Franklin-Reiter Rleated Message Attack**
である。

この攻撃手法は、公開鍵 `e` がいつもどおり 65537 であれば数十分かかるが、
今回は幸いなことに `e = 137` なので、1分未満で計算は完了する。

暗号文 `c1` `c2` から `key` を復元するコードは以下のようになる：

```sage
for r in rs:
    R.<x> = Zmod(n)[]
    f1 = x^e - c1
    f2 = (x + r)^e - c2 
    ans = -my_gcd(f1, f2).coefficients()[0]
    if ans != -1:
        key = long_to_bytes(int(ans))
```

あとは `key` を使って `encyprted_flag` を復号するだけである：

```sage
key = hashlib.sha256(key).digest()
aes_ecb = AES.new(key, AES.MODE_ECB)
print(aes_ecb.decrypt(encyprted_flag))
```

```
SECCON{Vim_has_a_command_to_do_rot13._g?_is_possible_to_do_so!!}
```
