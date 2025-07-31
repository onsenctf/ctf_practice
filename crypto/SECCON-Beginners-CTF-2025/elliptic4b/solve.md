# elliptic4b

## 脆弱性

有限加法群上で「負の整数か否か」という判定に役割を持たせようとしている点

## 解答

まず elliptic4b.py の7-12行目より、y成分が所与の乱数 `y` であるような楕円曲線 secp256k1 上の点を見つける必要がある。

```py
y = secrets.randbelow(secp256k1.p)
print(f"{y = }")
x = int(input("x = "))
if not secp256k1.is_point_on_curve((x, y)):
    print("// Not on curve!")
    exit(1)
```

楕円曲線 secp256k1 の定義を以下に示す。なお $p = 2^{256} - 2^{32} - 977$ である。

$$
y^2 \equiv x^3 + 7 \pmod p
$$

この定義より、以下の代数方程式の根を求めることにより目的の点を得る。

$$
x^3 - y^2 + 7 \equiv 0 \pmod p
$$

この根は sage の `roots` を使うことで以下のように求められる。（ただし、もとより `y` が楕円曲線上に存在し得ない値の場合は求解に失敗する。）

```py
p = 2**256 - 2**32 - 977
F = GF(p)
E = EllipticCurve(F, [0, 7])
X = PolynomialRing(F, 'X').gen()

r = remote('elliptic4b.challenges.beginners.seccon.jp', 9999)
r.recvuntil(b'y = ')
y = int(r.recvline().decode())

x = (X**3 - y**2 + 7).roots()[0][0]
```

次に elliptic4b.py の13-24行目より、上で求めた点 $P$ に対し、そのx成分が同一でありy成分が異なるような点 $Q = aP$ を生成する非負係数 $a$ を求める必要がある。

```py
a = int(input("a = "))
P = Point(x, y, secp256k1)
Q = a * P
if a < 0:
    print("// a must be non-negative!")
    exit(1)
if P.x != Q.x:
    print("// x-coordinates do not match!")
    exit(1)
if P.y == Q.y:
    print("// P and Q are the same point!")
    exit(1)
```

まず楕円曲線において、点 $P = (x, y)$ に対し $-P$ は $(x, -y)$ であるから、 $Q = -P = aP$ なる $a$ を選べばよい。また有限加法群の元 $g$ に対し $\operatorname{ord}(g) \cdot g = 0$ ゆえ $(\operatorname{ord}(g) - 1) \cdot g = -g$ である（ $\operatorname{ord}(g)$ は $g$ の位数を表す）。楕円曲線は有限加法群なので $a = \operatorname{ord}(P) - 1$ は条件を満たす。

位数の計算には sage の `order` を使い、以下のように目的の $a$ を求める。

```py
a = E.point((x, y)).order() - 1
```

$x, a$ をサーバに送信しフラグを得る。

```py
r.sendline(str(int(x)).encode())
r.sendline(str(int(a)).encode())

print(r.recvall().decode())
```

```
ctf4b{1et'5_b3c0m3_3xp3r7s_1n_3ll1p71c_curv35!}
```
