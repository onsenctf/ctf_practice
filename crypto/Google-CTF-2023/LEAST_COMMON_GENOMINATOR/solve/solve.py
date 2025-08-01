from Crypto.Util.number import inverse, GCD
from functools import reduce

def solve_unknown_increment(states, A, M):
    B = (states[1] - A * states[0]) % M
    return B

def solve_unknown_multiplier(states, M):
    A = (states[2] - states[1]) * inverse((states[1] - states[0]), M)
    return A

def solve_unknown_modulus(states):
    diffs = [X_1 - X_0 for X_0, X_1 in zip(states, states[1:])]
    multiples_of_M = [T_2 * T_0 - T_1 ** 2 for T_0, T_1, T_2, in zip(diffs, diffs[1:], diffs[2:])]
    M = reduce(GCD, multiples_of_M)
    return M

# 
seed = 211286818345627549183608678726370412218029639873054513839005340650674982169404937862395980568550063504804783328450267566224937880641772833325018028629959635
primes_arr = [seed] + list(map(int, open('dump.txt').read().split('\n')[:-1]))


M = solve_unknown_modulus(primes_arr)
A = solve_unknown_multiplier(primes_arr, M)
B = solve_unknown_increment(primes_arr, A, M)
print(f"n = {M}")
print(f"m = {A}")
print(f"c = {B}")
