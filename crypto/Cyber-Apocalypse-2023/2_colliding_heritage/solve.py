#!/usr/bin/env python3

import signal
from secrets import randbelow
from hashlib import md5
from Crypto.Util.number import isPrime, getPrime, long_to_bytes, bytes_to_long, inverse
from sage.all import * 

FLAG = "HTB{???????????????????????????}"


class MD5chnorr:

    def __init__(self):
        # while True:
        #     self.q = getPrime(128)
        #     self.p = 2*self.q + 1
        #     if isPrime(self.p):
        #         break
        self.p = 0x16dd987483c08aefa88f28147702e51eb
        self.sig1 =  (16140532026872297338095365539272234556, 143171456208932576363273329042088740961)
        self.sig2 = (191347737268393982670048338067500357704, 80642888714589697760439596955121395181)
        self.q = (self.p - 1) // 2
        self.g = 3
        f = GF(self.q)
        s1 = f(self.sig1[0])
        e1 = f(self.sig1[1])
        s2 = f(self.sig2[0])
        e2 = f(self.sig2[1])
        self.x = int((s1 - s2) / (e2 - e1))
        self.y = pow(self.g, self.x, self.p)

    def H(self, msg):
        return bytes_to_long(md5(msg).digest()) % self.q

    def sign(self, msg):
        k = self.H(msg + long_to_bytes(self.x))
        r = pow(self.g, k, self.p) % self.q
        e = self.H(long_to_bytes(r) + msg)
        s = (k - self.x * e) % self.q
        return (s, e)

    def verify(self, msg, sig):
        s, e = sig
        if not (0 < s < self.q):
            return False
        if not (0 < e < self.q):
            return False
        rv = pow(self.g, s, self.p) * pow(self.y, e, self.p) % self.p % self.q
        ev = self.H(long_to_bytes(rv) + msg)
        return ev == e


def menu():
    print('[S]ign a message')
    print('[V]erify a signature')
    return input('> ').upper()[0]


def main():
    md5chnorr = MD5chnorr()
    if True:
        # b'I am the left hand' == 4920616d20746865206c6566742068616e64
        msg = bytes.fromhex("4920616d20746865206c6566742068616e64")
        sig = md5chnorr.sign(msg)
        print(str(sig[0]) + '\n\n\n\n' + str(sig[1]))

    elif choice == 'V':
        msg = bytes.fromhex(input('Enter message> '))
        s = int(input('Enter s> '))
        e = int(input('Enter e> '))
        if md5chnorr.verify(msg, (s, e)):
            if msg == b'I am the left hand':
                print(FLAG)
            else:
                print('Valid signature!')
        else:
            print('Invalid signature!')

    else:
        print('Invalid choice...')


if __name__ == '__main__':
    main()
