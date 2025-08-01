from Crypto.Util.number import *
p2 = bytes_to_long(b'printed on flammable material so that spies could')
c2 = 0x06e2f65a4c256d0ba8ada164cecd329cae436069f83476e91757e91bd4a4cce2c60a8f9aac8cb14210d55253cd787c0f6a
key = p2^c2
c3 = 0x03f9ea574c267249b2b1ef5d91cd3c99904a3f75873871e94157df0fcbb5d1eab94f938600000000000000000000000000
print(long_to_bytes(c3^key))
