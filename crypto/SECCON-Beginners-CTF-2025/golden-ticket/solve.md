# Golden Ticket

## 脆弱性

* 復号オラクルの入力も PKCS \#7 パディングされている点
* 復号オラクルに入力する IV をこちらが指定できる点

## 解答

まず golden-ticket.py の 80 行目 ( `print("flag:", flag)` ) に到達できればフラグが見られることがわかる。

```py
    if i == 4:
        consume_ticket(golden=1)
        print("flag:", flag)
```

この関数 `consume_ticket` は、以下で定義されているように、 `ENC_TICKET` と `DEC_TICKET` を、最大3枚ずつ使って `GOLDEN_TICKET` を1枚以上獲得できていれば `exit` することなく処理が終了する。

```py
def consume_ticket(enc: int = 0, dec: int = 0, golden: int = 0):
    global ENC_TICKET, DEC_TICKET, GOLDEN_TICKET
    if ENC_TICKET < enc or DEC_TICKET < dec or GOLDEN_TICKET < golden:
        print("Not enough tickets.")
        exit(1)
    ENC_TICKET -= enc
    DEC_TICKET -= dec
    GOLDEN_TICKET -= golden
```

`GOLDEN_TICKET` を獲得するには、 golden-ticket.py の 74 行目 ( `GOLDEN_TICKET += 1337` ) に到達する必要がある。65-76 行目を以下に示す。

```py
    if i == 3:
        print("challenge:", challenge.hex())
        answer = bytes.fromhex(input("answer> "))
        if len(answer) != len(challenge) + 16:
            print("Wrong length.")
            continue
        cipher = AES.new(key, AES.MODE_CBC, iv=answer[:16])
        if cipher.decrypt(answer[16:]) == challenge:
            print("Correct!")
            GOLDEN_TICKET += 1337
        else:
            print("Wrong :(")
```

この74行目に到達するには、条件 `cipher.decrypt(answer[16:]) == challenge` を満たす必要がある。言い換えると、 AES-CBC で復号すると `challenge` になるような暗号文 $\verb|ans|$ と初期化ベクトル $\verb|IV'|$ を求める必要がある。そこで、AES のブロック復号関数を $D$ 、 `challenge` を 16 バイトごとに区切ったものを $\verb|chall| = \verb|chall|_0 || ... || \verb|chall|_5$ と呼び $\verb|ans|$ を 16 バイトごとに区切ったものを $\verb|ans| = \verb|ans|_0 || ... || \verb|ans|_5$ と呼ぶこととし、AES-CBC の定義に基づき、これを数式で表すと以下のようになる。

$$D(\verb|ans|_0) \oplus \verb|IV|' = \verb|chall|_0$$
$$D(\verb|ans|_1) \oplus \verb|ans|_0 = \verb|chall|_1$$
$$\cdots$$
$$D(\verb|ans|_5) \oplus \verb|ans|_4 = \verb|chall|_5$$

上式を求めるべき $\verb|IV'|$ および $\verb|ans|_i$ について整理すると

$$\verb|IV'| = D(\verb|ans|_0) \oplus \verb|chall|_0$$
$$\verb|ans|_0 = D(\verb|ans|_1) \oplus \verb|chall|_1$$
$$\cdots$$
$$\verb|ans|_4 = D(\verb|ans|_5) \oplus \verb|chall|_4$$

となる。また AES のブロック暗号化関数を $E$ とし $E(D(x)) = x$ であることを鑑みると、

$$\verb|ans|_0 =  E(\verb|chall|_0 \oplus \verb|IV|')$$
$$\cdots$$
$$\verb|ans|_4 = E(\verb|chall|_4 \oplus \verb|ans|_3)$$
$$\verb|ans|_5 = E(\verb|chall|_5 \oplus \verb|ans|_4)$$

とも書ける。以降では、この性質を用いて $\verb|IV|', \verb|ans|$ を求めることを考える。

さて、前述のとおり、ユーザには `ENC_TICKET` と `DEC_TICKET` が3枚ずつ与えられている。 `ENC_TICKET` を1枚消費することで 47-54 行目の暗号化オラクルにアクセスでき、 `DEC_TICKET` を1枚消費することで 56-63 行目の復号オラクルにアクセスできる。 47-63 行目を以下に示す。

```py
    if i == 1:
        consume_ticket(enc=1)
        pt = bytes.fromhex(input("pt> "))
        if len(pt) > 16:
            print("Input must not be longer than 16 bytes.")
            continue
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        print(f"ct:", cipher.encrypt(pad(pt, 16)).hex())

    if i == 2:
        consume_ticket(dec=1)
        ct = bytes.fromhex(input("ct> "))
        if len(ct) > 16:
            print("Input must not be longer than 16 bytes.")
            continue
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        print("pt:", cipher.decrypt(pad(ct, 16)).hex())
```

暗号化オラクルと復号オラクルへの入力はともに PKCS \#7 パディングされている。そこで、入力 $x$ をブロック長である 16 バイトに限定すると、これらのオラクル $\verb|Enc|, \verb|Dec|$ はそれぞれ、

$$\verb|Enc|(x) = E(x \oplus \verb|IV|) || E(\verb|10...10| \oplus E(x \oplus \verb|IV|))$$
$$\verb|Dec|(x) = D(x) \oplus \verb|IV| || D(\verb|10...10|) \oplus x$$

と書ける（ $\verb|IV|$ はサーバが選んだ初期化ベクトル）。このとき、 

$$\verb|Dec|(\verb|10...10|) =  D(\verb|10...10|) \oplus \verb|IV|  || D(\verb|10...10|) \oplus \verb|10...10|$$

であるので、左のブロックと右のブロックを $m_0, m_1$ と書くとすると、

$$\verb|IV| = m_0 \oplus m_1 \oplus \verb|10...10|$$
$$D(\verb|10...10|) =m_1 \oplus \verb|10...10|$$ 

を得る。ここで $\verb|ans|_2 = \verb|10...10|$ を選べば、上述の性質より

$$
\verb|ans|_1 = D(\verb|ans|_2) \oplus \verb|chall|_2 = D(\verb|10...10|) \oplus \verb|chall|_2
$$

が言える。また

$$\verb|Dec|(\verb|ans|_1) = D(\verb|ans|_1) \oplus \verb|IV| || ...$$
$$\verb|Dec|(\verb|ans|_0) = D(\verb|ans|_0) \oplus \verb|IV| || ...$$

の各右辺の左ブロックに $\verb|IV|$ を xor することで $D(\verb|ans|_1), D(\verb|ans|_0)$ が求まることにより

$$\verb|ans|_0 = D(\verb|ans|_1) \oplus \verb|chall|_1$$
$$\verb|IV|' = D(\verb|ans|_0) \oplus \verb|chall|_0$$

を得る。以上より `DEC_TICKET` を3枚消費して $\verb|IV|', \verb|ans|_0, \verb|ans|_1, \verb|ans|_2$ が求まった。 次に、 $\verb|Enc|$ の定義より $i = 3, 4, 5$ に対し

$$\verb|Enc|(\verb|chall|\_i \oplus \verb|ans|\_{i-1} \oplus \verb|IV|) = E(\verb|chall|\_i \oplus \verb|ans|\_{i-1}) || ... = \verb|ans|\_i || ...$$

であることから $\verb|ans|_i$ を得る。以上の計算行うプログラムを実行しフラグを得る。

```py
from pwn import *

r = remote('golden-ticket.challenges.beginners.seccon.jp', 9999)

def block(s, blklen):
    return [int(s[i:i+blklen], 16) for i in range(0, len(s), blklen)]

def enc(x):
    r.sendlineafter(b'> ', b'1')
    r.sendlineafter(b'pt> ', hex(x)[2:].encode())
    r.recvuntil(b'ct: ')
    return block(r.recvline().decode().strip(), 32)

def dec(x):
    r.sendlineafter(b'> ', b'2')
    r.sendlineafter(b'ct> ', hex(x)[2:].encode())
    r.recvuntil(b'pt: ')
    return block(r.recvline().decode().strip(), 32)

r.sendlineafter(b'> ', b'3')
r.recvuntil(b'challenge: ')
chall = block(r.recvline().decode().strip(), 32)
r.sendline()

ans = [0] * 6
pad = 0x10101010101010101010101010101010
m0, m1 = dec(pad)
iv = m0 ^ m1 ^ pad
ans[2] = pad 
ans[1] = m1 ^ pad ^ chall[2] 
ans[0] = dec(ans[1])[0] ^ iv ^ chall[1]
iv_    = dec(ans[0])[0] ^ iv ^ chall[0]
ans[3] = enc(chall[3] ^ ans[2] ^ iv)[0]
ans[4] = enc(chall[4] ^ ans[3] ^ iv)[0]
ans[5] = enc(chall[5] ^ ans[4] ^ iv)[0]

ans_hex = hex(iv_)[2:] + ''.join([hex(ans[i])[2:] for i in range(6)])

r.sendline(b'3')
r.sendlineafter(b'answer> ', ans_hex.encode())

r.sendline(b'4')
r.recvuntil(b'flag: ')
print(r.recvline().decode())
```

```
ctf4b{u_wi11_b3_1nv173d_t0_7h3_ch0c0l4t3_f4c70ry_1337_t1m35}
```
