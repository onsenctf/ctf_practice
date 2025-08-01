# My solution of CoughingFox2

## Observation
[`problem.py`](../given_files/problem.py)を眺めると、以下のようなことが分かる。
* `ROL`というのは、どうも循環左シフトのことらしい (GPT先生より)。
* `key`は、最初に`getrandbits`されたものを基準に`ROL`されて32回変動する。
* `cipher`は`flag^key`で初期化され、更新される`key`によって32回マスクされる。
* [`output.txt`](../given_files/problem.py)で与えられるのは、最後の`key`と`cipher`の値。
* `cipher`のビット長は`436`。

## Answer
まず最後の`cipher`と`key`の値が与えられているのだから、`cipher ^ key`によって31回目のマスク後の`cipher`の値を求められる。

問題は31回目の`key`をどう求めるかということである。鍵の更新式をみると、

```
key = ROL(key, pow(cipher, 3, length))
```

となっている。これを最後の(32回目の)`key`の生成に当てはめて考えると、31回目の`key`を、31回目の`cipher`の値を用いた`pow(cipher,3,length)`ビット循環左シフトしているということを意味している。

上で31回目の`cipher`の値は求めることができているので、`ROL`の逆演算`ROR`を定義し、`pow(cipher,3,length)`ビット右循環シフトしてやればよい。

上の作業を繰り返し行えば芋づる式に`key`と`cipher`が求まっていく。

なお、正確に`ROR`を定義するためには **`flag`の** `length`の正確な値が必要である。なぜなら、元の`ROL`の循環長が`flag`の`length`に依存しているからだ。

これは **`cipher`の**  `length`で仮置きしておいて、プラスマイナス5程度の値を試す(あるいはプログラムを書く)のがよいと思う。最終的には以下のようなプログラムになる：
```python
from Crypto.Util.number import *

def ROR(bits, N):
    for _ in range(N):
        bits = ((bits >> 1) | (bits << (length - 1))) & ((2 ** length) - 1)
    return bits

length = 439 # cannot be determined by calculation

key = 364765105385226228888267246885507128079813677318333502635464281930855331056070734926401965510936356014326979260977790597194503012948
cipher = 92499232109251162138344223189844914420326826743556872876639400853892198641955596900058352490329330224967987380962193017044830636379

for i in range(32):
    cipher ^= key
    key = ROR(key, pow(cipher,3, length))

cipher ^= key

print(long_to_bytes(cipher).decode())
```

```
ctf4b{SemiCIRCLErCanalsHaveBeenConqueredByTheCIRCLE!!!}
```
