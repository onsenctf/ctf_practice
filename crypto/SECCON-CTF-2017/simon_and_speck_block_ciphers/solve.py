import string
from pwn import *
from simon import SimonCipher

plain  = 0x6d564d37426e6e71
cipher = 0xbb5d12ba422834b5

def to_int(str):
    return int("0x" + "".join(list(map(lambda c: hex(ord(c))[2:], str))), 16)

s = iters.mbruteforce(lambda x: SimonCipher(to_int("SECCON{" +"x"+ "}"), 96, 64).decrypt(cipher) == plain, string.printable, length = 4, method = 'fixed')

print("SECCON{" +s+ "}")
