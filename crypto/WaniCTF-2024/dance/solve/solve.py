from Crypto.Util.number import *
from itertools import product

from chall import *
from mycipher import *


for minutes, sec, r in product(range(61), range(61), range(11)):
    username = 'gureisya'
    data1 = f'user: {username}, {minutes}:{sec}'
    data2 = f'{username}'+str(r)
    token = make_token(data1, data2)
    sha256 = hashlib.sha256()
    sha256.update(token.encode())
    key = sha256.hexdigest()[:32]
    nonce = token[:12]

    m = MyCipher(key.encode(), nonce.encode()).encrypt(long_to_bytes(int('061ff06da6fbf8efcd2ca0c1d3b236aede3f5d4b6e8ea24179',16)))
    if b'FLAG' in m:
        print(m)
        break
