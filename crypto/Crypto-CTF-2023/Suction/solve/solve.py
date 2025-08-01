# given
PKEY = 55208723145458976481271800608918815438075571763947979755496510859604544396672
ENC = 127194641882350916936065994389482700479720132804140137082316257506737630761

# solver
from Crypto.Util.number import *
from factordb.factordb import *

n = int(bin(PKEY)[2:-8] + '0'*8, 2)
# factors = []
# for i in range(256):
#     f = FactorDB(n+i)
#     f.connect()
#     factors = f.get_factor_list()
#     if len(factors) == 2 and factors[0].bit_length() == factors[1].bit_length():
#         print(factors)
#         break
factors = [188473222069998143349386719941755726311, 292926085409388790329114797826820624883]
p = factors[0]
q = factors[1]

e = int(bin(PKEY)[-8:] + '0'*8, 2)
e_candidates = []
for i in range(2**8):
    if isPrime(e+i):
        e_candidates.append(e+i)

c = int(bin(ENC)[2:] + '0'*8, 2)
for e_ in e_candidates:
    d_ = pow(e_, -1, (p-1)*(q-1))
    for i in range(2**8):
        s ="".join([chr(c) for c in long_to_bytes(pow(c+i,d_,p*q))])
        if s.isprintable():
            print('CCTF{'+s+'}')
    
