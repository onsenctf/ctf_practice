#!/usr/local/bin/python
import os
from Crypto.Util.number import getStrongPrime
from Crypto.Cipher import AES

N_BITS = 1024

class ARES(object):
    """ARES: Advanced RSA Encryption Standard"""
    def __init__(self, key: bytes, p: int, q: int, e: int):
        self.key = key
        self.n = p * q
        self.e = e
        self.d = pow(self.e, -1, (p-1)*(q-1))

    def encrypt(self, m: int):
        iv = os.urandom(16)
        c1 = int.to_bytes(pow(m, self.e, self.n), N_BITS//8, 'big')
        c2 = AES.new(self.key, AES.MODE_CBC, iv).encrypt(c1)
        return iv + c2

    def decrypt(self, c: bytes):
        iv, c2 = c[:16], c[16:]
        c1 = AES.new(self.key, AES.MODE_CBC, iv).decrypt(c2)
        print('aaaaaaaa: ',c1.hex())
        m = pow(int.from_bytes(c1, 'big'), self.d, self.n)
        return m, c1.hex()

if __name__ == '__main__':
    key = os.urandom(16)
    p = getStrongPrime(N_BITS//2)
    q = getStrongPrime(N_BITS//2)
    n = p * q
    print(n)
    e = 65537

    FLAG  = os.getenv("FLAG", "ctf4b{*** REDACTED ***}").encode()
    FLAG += os.urandom(16)
    assert len(FLAG) < N_BITS//8
    m = int.from_bytes(FLAG, 'big')
    c = pow(m, e, n)
    print("enc_flag:", int.to_bytes(c, N_BITS//8, 'big').hex())

    ares = ARES(key, p, q, e)

    print("1. Encrypt with ARES" "\n"\
          "2. Decrypt with ARES")
    while True:
        choice = int(input('> '))
        if choice == 1:
            m = int(input('m: '))
            assert m < n, "Plaintext too big"
            c = ares.encrypt(m)
            print("c:", c.hex())

        elif choice == 2:
            c = bytes.fromhex(input('c: '))
            assert len(c) > 16 and len(c) % 16 == 0, "Invalid ciphertext"
            m, he = ares.decrypt(c)
            print("m:", m)
            print('h:', he)

        else:
            break
