from Crypto.Util.number import bytes_to_long, isPrime
from secret import (
    x,
    p,
    q,
)  # x, p, q are secret values, please derive them from the provided other values.
import gmpy2


def is_square(n: int):
    return gmpy2.isqrt(n) ** 2 == n


assert isPrime(p)
assert isPrime(q)
assert p != q

a = p - x
b = q - x
assert is_square(x) and is_square(a) and is_square(b)

n = p * q
e = 65537
flag = b"ctf4b{dummy_f14g}"
mes = bytes_to_long(flag)
c = pow(mes, e, n)

print(f"n = {n}")
print(f"e = {e}")
print(f"cipher = {c}")
print(f"ab = {a * b}")

# clews of factors
assert gmpy2.mpz(a) % 4701715889239073150754995341656203385876367121921416809690629011826585737797672332435916637751589158510308840818034029338373257253382781336806660731169 == 0
assert gmpy2.mpz(b) % 35760393478073168120554460439408418517938869000491575971977265241403459560088076621005967604705616322055977691364792995889012788657592539661 == 0

