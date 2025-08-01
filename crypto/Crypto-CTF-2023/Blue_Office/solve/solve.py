# given
def reseed(s):
	return s * 214013 + 2531011
def encrypt(s, msg):
	assert s <= 2**32
	c, d = 0, s
	enc, l = b'', len(msg)
	while c < l:
		d = reseed(d)
		enc += (msg[c] ^ ((d >> 16) & 0xff)).to_bytes(1, 'big')
		c += 1
	return enc

# cut lower 3rd byte 
def cut(s):
    return hex(s)[-6:-4]

# search
i = 0
while not ('f3' == cut(reseed(i)) and \
	       '88' == cut(reseed(reseed(i))) and \
	       '37' == cut(reseed(reseed(reseed(i)))) and \
	       '50' == cut(reseed(reseed(reseed(reseed(i)))))):
    i += 1

seed = i
enc = 0xb0cb631639f8a5ab20ff7385926383f89a71bbc4ed2d57142e05f39d434fce

from Crypto.Util.number import *
print(encrypt(seed, long_to_bytes(enc)).decode())

