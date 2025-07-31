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
