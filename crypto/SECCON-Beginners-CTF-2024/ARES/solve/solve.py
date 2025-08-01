from Crypto.Util.number import *
from pwn import *

#
# helpers
#
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


#
# main
#
m = '123456789'  # whatever will be fine
iv, c = ARES_enc(m)
c_ = RSA_enc(m)

xor_ = lambda a, b, c: (int(a, 16) ^ int(b, 16) ^ int(c, 16)).to_bytes(16, 'big').hex() 
for i in range(8,1,-1):
    c = c[:i-2] + [xor_(c[i-2], c_[i-1], ef[i-1])] + c[i-1:]
    c_ = AES_dec(iv, ''.join(c))
iv = xor_(iv, c_[0], ef[0])

print(long_to_bytes(int(ARES_dec(iv, ''.join(c)))))
