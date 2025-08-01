# Ancient Encodings
(2023/04/09追記：配布ファイルの再配布が禁止されていたことに気づいたため，これらを削除しました．)

## 概要
`output.txt`と`sorce.py`が与えられている．

`source.py`を見るにbase64でフラグをエンコードしているようなので，これをデコードすればよい．

## 解答
```
>>> from Crypto.Util.number import *
>>> from base64 import *
>>> b64decode(long_to_bytes(int(open("output.txt", "r").read(), 16)))
b'HTB{1n_y0ur_j0urn3y_y0u_wi1l_se3_th15_enc0d1ngs_ev3rywher3}'
```

