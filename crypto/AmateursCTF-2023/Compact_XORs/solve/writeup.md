# My solution for Compact_XORs

## 解答
[fleg](../given_files/fleg) に書かれている、`610c6115651072014317463d73127613732c73036102653a6217742b701c61086e1a651d742b69075f2f6c0d69075f2c690e681c5f673604650364023944` という16進数列を2ケタずつ見てみると、`61` `65` `72` といった印字可能なascii文字のあいだに、`0c` `15` `10` といった印字不可能なものが並んでいることが分かる。

題の "Compact_XORs" から察するに、これらを XOR していけばいい：
```console
$ python3
>>> fleg = '610c6115651072014317463d73127613732c73036102653a6217742b701c61086e1a651d742b69075f2f6c0d69075f2c690e681c5f673604650364023944'
>>> for i in range(len(fleg)//4):
...     print(chr(int(fleg[i*4:i*4+2], 16) ^ int(fleg[i*4+2:i*4+4], 16)), end='')
...
mtusT{ae_pc_u_litx_npansgt82ff}
```
フラグのような文字は得られたが、何文字か抜け落ちてしまっている。

そこで、もともと印字可能だったものはXORせず出力するようなコードを追記してみる：
```console
>>> for i in range(len(fleg)//4):
...     print(chr(int(fleg[i*4:i*4+2],16)),end='')
...     print(chr(int(fleg[i*4:i*4+2], 16) ^ int(fleg[i*4+2:i*4+4], 16)), end='')
...
amateursCTF{saves_space_but_plaintext_in_plain_sight_862efdf9}
```
フラグが得られた。
