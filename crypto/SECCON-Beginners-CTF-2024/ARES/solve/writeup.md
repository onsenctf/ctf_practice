# My solution for ARES

以下 CBC モードの AES を単に AES と呼ぶ。

## 概要

$\textsf{ARES}.\textsf{Enc} = \textsf{AES}.\textsf{Enc}(\textsf{RSA}.\textsf{Enc}(m))$,
$\textsf{ARES}.\textsf{Dec} = \textsf{RSA}.\textsf{Dec}(\textsf{AES}.\textsf{Dec}(c))$
であるような、 $\textsf{ARES}$ という暗号方式に関する問題。

サーバーにアクセスすると、まずはじめにフラグ $\textsf{f}$ を $\textsf{RSA}$ で暗号化した値 `enc_flag` ( $\textsf{ef}$ と呼ぶことにする) を入手することができる。
そしてこれ以降、サーバーには何度でも $\textsf{ARES}.\textsf{Enc}$ と $\textsf{ARES}.\textsf{Dec}$ をリクエストできる。

定義より $\textsf{RSA}.\textsf{Enc}(\textsf{f}) = \textsf{ef}$ なので、 $\textsf{AES}.\textsf{Dec}(c) = \textsf{ef}$ なる $c$ を用意できれば、そのような $c$ を用いて $\textsf{ARES}.\textsf{Dec}(c)$ をサーバーへリクエストすることで $\textsf{ARES}.\textsf{Dec}(c) = \textsf{RSA}.\textsf{Dec}(\textsf{AES}.\textsf{Dec}(c)) = \textsf{RSA}.\textsf{Dec}(\textsf{ef}) = \textsf{f}$ となりフラグが求まることが分かる。

## AES の復号オラクルを作る

暗号文 $c$ を入力すると、十分現実的な確率で対応する平文 $m$ を出力してくれるアルゴリズムのことを、暗号理論の言葉で **復号オラクル** と呼ぶ (要は $\textsf{AES}.\textsf{Dec}$ を模倣するアルゴリズムのこと)。

$\textsf{ARES}$ の復号方式に着目すると、この問題では $\textsf{AES}$ の復号オラクルをこちら側で用意できることが分かる。
具体的には、 $\textsf{RSA}.\textsf{Enc}(\textsf{ARES}.\textsf{Dec}(c))$ が復号オラクルとなる。なお、 $\textsf{RSA}.\textsf{Enc}$ に必要な公開鍵は、サーバーに -1 を暗号化してもらい、得られた暗号文を再度サーバーに復号してもらい、その値に 1 を加えることで得られる。

ここまでを python で書くと以下のようになる：

```python
r = remote('ares.beginners.seccon.games', 5000)

as_blks = lambda c: [c[i*32: (i+1)*32] for i in range(8)]

r.recvuntil(b'enc_flag: '); ef = as_blks(r.recvline().decode())

def ARES_enc(m: str) -> str:
    r.sendlineafter(b'> ', b'1')
    r.sendlineafter(b'm: ', m.encode())
    r.recvuntil(b'c: '); c_str = r.recvline().decode()
    iv, c2 = c_str[:32], c_str[32:-1]
    return iv, as_blks(c2)

def ARES_dec(iv: str, c: str) -> str:
    r.sendlineafter(b'> ', b'2')
    r.sendlineafter(b'c: ', (iv+c).encode())
    r.recvuntil(b'm: '); m_str = r.recvline().decode()
    return m_str

def get_n():
    iv, c2 = ARES_enc('-1')
    return int(ARES_dec(iv, ''.join(c2))) + 1

n = get_n()
def RSA_enc(m: str) -> str:
    return as_blks(hex(pow(int(m), 65537, n))[2:])

def AES_dec(iv: str, c: str) -> str:
    m_str = ARES_dec(iv, c)
    return RSA_enc(m_str)
```

## 復号オラクルの応答が `enc_flag` になるような暗号文を作る

AES 暗号文の第 $k$ ブロックを $c_k$ 、その復号結果に対応する平文ブロックを $\overline{c_k}$ 、ブロック単位の復号の関数を $\textsf{dec}$ とすると、 CBC モードの復号方法より $\overline{c_k} = \textsf{dec}(c_k) \oplus c_{k-1}$ が成り立つ。

概要で述べた通り、本問では $\textsf{AES}.\textsf{Dec}(c) = \textsf{ef}$ なる $c$ を作ることができればフラグが求まるので、上式において $\overline{c_k}$ が $\textsf{ef}\_k$ ( $\textsf{ef}$ の16バイトごとに区切ったときの $k$ 番目のブロック) となるような $c_{k-1}'$ を各 $k$ について求めれば良いことが分かる。

上式を等式変形すると $\overline{c_k} \oplus \overline{c_k} \oplus \textsf{ef}\_k = \textsf{dec}(c_k) \oplus c_{k-1} \oplus \overline{c_k} \oplus \textsf{ef}\_k$ 、すなわち $\textsf{ef}\_k = \textsf{dec}(c_k) \oplus c_{k-1} \oplus \overline{c_k} \oplus \textsf{ef}\_k$ であるから、 $c_{k-1}'$ として $c_{k-1} \oplus \overline{c_k} \oplus \textsf{ef}_k$ を選べばよいことが分かる。

この方法を末尾ブロックから先頭に向かって順に行っていけば、最終的に所望の $c$ が得られる:

```python
m = '123456789'  # whatever will be fine
iv, c = ARES_enc(m)
c_ = RSA_enc(m)

xor_ = lambda a, b, c: (int(a, 16) ^ int(b, 16) ^ int(c, 16)).to_bytes(16, 'big').hex() 
for i in range(8,1,-1):
    c = c[:i-2] + [xor_(c[i-2], c_[i-1], ef[i-1])] + c[i-1:]
    c_ = AES_dec(iv, ''.join(c))
iv = xor_(iv, c_[0], ef[0])

print(long_to_bytes(int(ARES_dec(iv, ''.join(c)))))
```

## （補足）フラグが得られない場合について

[solver](./solve.py) を実行してもフラグが得られない場合がある。
これは $\textsf{AES}.\textsf{Dec}(c)$ が $n$ より大きい値となってしまうことがあるからである。

復号オラクルは具体的には $\textsf{RSA}.\textsf{Enc}(\textsf{RSA}.\textsf{Dec}(\textsf{AES}.\textsf{Dec}(c)))$
を計算しており、最後の $\textsf{RSA}.\textsf{Enc}$ は $n$ を超えることはないため、上記の場合は $\textsf{AES}.\textsf{Dec}(c)$ を計算したことにはならない。
