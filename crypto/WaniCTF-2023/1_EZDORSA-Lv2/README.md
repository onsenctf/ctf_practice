# EZDORSA_Lv2

## 解答
まず `chall.py` を見て，RSA暗号の公開鍵 `e` の値が7と小さいことに気づく (一般的には `0x10001` が使われる). 加えて，暗号文 `c` にちょこっとだけ細工 (11行目) が施されていることにも注意する．

```
$ python3
>>> exec(open('out.txt').read())
>>> c //= pow(5,100,n)
>>> from gmpy2 import iroot
>>> from Crypto.Util.number import long_to_bytes
>>> long_to_bytes(iroot(c,7)[0])
b'FLAG{l0w_3xp0n3nt_4ttAck}'
```

上のコードにおける`exec(open('out.txt').read())`というのは，`out.txt`をpythonコードとして実行するという意味である．本問では `out.txt` がたまたま python の代入文と同じ構文で記述されていたため，このようにしても問題ないのである． (一応書いておくと， `out.txt` に，例えば `n := 239209309423...` のように書かれていると，このコードは動かない．)
