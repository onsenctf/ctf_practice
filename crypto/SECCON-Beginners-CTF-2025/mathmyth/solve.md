# mathmyth

## 脆弱性

素数 $q$ が効率的に探索できてしまう点

## 解答

problem.py の27行目より、RSA暗号の秘密鍵 $q$ は280bitの素数である。

```py
    q = getPrime(BITS_q)
```

また28-30行目は以下のようになっている。

```py
    cand = q * q * next_prime(r) + g(q, salt) * r
    if isPrime(cand):
        p = cand
```

よってRSAの公開鍵 $n = p \cdot q$ は $q$ を用いて、

$$
n = (q^2 \cdot \verb|next_prime|(r) + \verb|g|(q, \verb|salt|) \cdot r) \cdot q
$$

なる素数とわかる。また、簡単な探索により $\verb|next_prime|(r) = r + 88$ とわかる。さらに、problem.py の12-16行目より $\verb|g|(q, \verb|salt|)$ は 512bit の乱数とみて差し支えない：

```py
def g(q: int, salt: int) -> int:
    q_bytes = q.to_bytes((q.bit_length() + 7) // 8, "big")
    salt_bytes = salt.to_bytes(16, "big")
    h = hashlib.sha512(q_bytes + salt_bytes).digest()
    return int.from_bytes(h, "big")
```

よって $n$ は以下のように書きなおせる（ただし $g = \verb|g|(q, \verb|salt|)$ とする）。

$$
n = (r + 88) \cdot q^3 + g \cdot r \cdot q
$$

このとき、

$$
n \equiv 88 \cdot q^3 \pmod r 
$$

である。また $q$ は定義より 280bit であり、 $r$ は調べると 222bit と $q$ より小さい。よって方程式

$$
n \equiv 88 \cdot x^3 \pmod r
$$

を満たす $r$ 未満の適切な自然数 $x$ と自然数 $k$ が存在し、 $q$ は

$$
q = k \cdot r + x
$$

と書ける。なぜなら

$$
88 \cdot q^3 \equiv 88 \cdot (k^3 \cdot r^3 + 3 \cdot k^2 \cdot r^2 \cdot x + 3 \cdot k \cdot r \cdot x^2 + x^3) \equiv 88 \cdot x^3 \equiv n \pmod r
$$

だからである。

フラグを得るために、 $q$ の値を求めることを考える。まず上の方程式を満たす自然数 $x$ の候補は sage の `roots` を用いることにより以下のように求められる（x の大文字と小文字の違いに注意）。

```py
X = PolynomialRing(Zmod(r), 'X').gen()
xs = [int(x) for x in (88*X**3 - n).roots(multiplicities=false)]
```

次に $q = k \cdot r + x$ なる自然数 $k$ を探索する。まず $n$ の定義より

$$
q = \sqrt[3]{\frac{n - g \cdot r \cdot q}{r + 88}}
$$

である。 $g$ は 512bit であるため $g < 2^{513}$ であり、 $q$ は 280bit であるため $q < 2^{281}$ である。よって

$$
\sqrt[3]{\frac{n - 2^{513 + 281} \cdot r}{r + 88}} < q (= k \cdot r + x) <  \sqrt[3]{\frac{n}{r + 88}}\\
\iff \frac{\sqrt[3]{\frac{n - 2^{513 + 281} \cdot r}{r + 88}}}{r} < k + \frac{x}{r} \ (\fallingdotseq k) < \frac{\sqrt[3]{\frac{n}{r + 88}}}{r}
$$

が成り立つ。左辺と右辺の差を sage で求めることにより $k$ の探索範囲を計算すると、これは 2495とわかる。よって $k$ の探索は即座に完了する。したがって左辺値から探索を開始し $q$ を求めることによりフラグを得る。

```py
for x in xs:
    for k in range(2495):
        q = (Integer((n - 2**(513+281)*r)//(88+r)).nth_root(3, True)[0] // r + k) * r + x
        if n % q == 0:
            p = n // q
            print(long_to_bytes(pow(c, pow(e, -1, (p-1)*(q-1)), n)).decode())
```

```
ctf4b{LLM5_4r3_k1ll1n9_my_pr0bl3m}
```
