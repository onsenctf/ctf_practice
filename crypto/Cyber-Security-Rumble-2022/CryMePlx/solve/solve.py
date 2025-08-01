from pwn import *
import binascii

context.log_level = 'debug'
p = remote('chall.rumble.host', 2734)

# unhexlify : 16進数表記の文字列の表すバイナリデータを返す．
enc_flag = binascii.unhexlify(p.recvline().strip())
input = 'A' * len(enc_flag)
p.sendlineafter('Encrypt this string:', input)
enc_input = binascii.unhexlify(p.recvline().strip())

flag = xor(input, enc_input, enc_flag)
print(flag)
