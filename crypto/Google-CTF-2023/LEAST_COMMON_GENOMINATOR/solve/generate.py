from secret import config
from Crypto.PublicKey import RSA
from Crypto.Util.number import *

class LCG:
    lcg_m = config.m
    lcg_c = config.c
    lcg_n = config.n

    def __init__(self, lcg_s):
        self.state = lcg_s

    def next(self):
        self.state = (self.state * self.lcg_m + self.lcg_c) % self.lcg_n
        return self.state

if __name__ == '__main__':

    assert 4096 % config.it == 0
    assert config.it == 8
    assert 4096 % config.bits == 0
    assert config.bits == 512

    # Find prime value of specified bits a specified amount of times
    seed = 211286818345627549183608678726370412218029639873054513839005340650674982169404937862395980568550063504804783328450267566224937880641772833325018028629959635
    lcg = LCG(seed)
    primes_arr = []
    
    dump = True
    dump = False
    items = 0
    dump_file = open("dump.txt", "w")

    primes_n = 1
    while True:
        for i in range(config.it):
            while True:
                prime_candidate = lcg.next()
                if dump:
                    dump_file.write(str(prime_candidate) + '\n')
                    items += 1
                    if items == 6:
                        dump = False
                        dump_file.close()
                if not isPrime(prime_candidate):
                    continue
                elif prime_candidate.bit_length() != config.bits:
                    continue
                else:
                    primes_n *= prime_candidate
                    primes_arr.append(prime_candidate)
                    break
        
        # Check bit length
        if primes_n.bit_length() > 4096:
            print("bit length", primes_n.bit_length())
            primes_arr.clear()
            primes_n = 1
            continue
        else:
            break

    # Create public key 'n'
    n = 1
    for j in primes_arr:
        n *= j
    print("[+] Public Key: ", n)
    print("[+] size: ", n.bit_length(), "bits")

    # Calculate totient 'Phi(n)'
    phi = 1
    for k in primes_arr:
        phi *= (k - 1)

    # Calculate private key 'd'
    d = pow(config.e, -1, phi)
    f = 0x0276f9162713d96423aca40a0a174cf129e6407c3ef4529b959ac53d99e0398182f6635725c0c60739a36081933b3248eb3c4ed61512329067dd5ae2226f9a607339b9cee7a31e1df39253099d6f01b57aa40e4598674bee9176253422c2a1e074c208e1bc21a8a5b67280a17ca70f094e4662a7ffff4371d655d8b4d91e8052bbab40a61565b469983373f1133f624289b95cf8b4f8a143dcfd05569e1441d3da5e9c644d049d1510f32bfbaf3a613e31fb5504a03cb88a47f35eeedefdf4df3ffebb3c46748bdcca512ea490ede8d732e355d2eef5639193fd97aca177f92069bd36b04fc0be2ccc61de239c461dced5a74c5a0ede0f2fd3cc3b2bf1076e501f50e371909894b6fc17509d87542b2ed04314fe70ab5aa1e121320dd1d9c786c046631e0526277d17baf9cf7ae7a268244709c1b547b748a41e25d86ed2f2089c7464091b4990ad0041afb30801353d70d1e51c42d74b072c8abd37f5f464e14db67b58915ca99a9510fdccd1d0f9f4de3b7e4306fff6033b0bdc10792980a4039232f42789ed3b380b4fc61c13914729d710f55af3e4516a8dd1b1d6066d8554a6d660ad703f33e9f38b9bf36f76b9ba39153c3cea92546e68eab4b34a1f9e2a0fcde9259320d81b36694c6d83174927b0db5425971ef0703ad9edcc7abcefd99c4e5af815adc1d0f16ef3eb09377ad5203fdb4b6b90796813109eea17134c
    print(long_to_bytes(pow(f,d,n)))

    # Generate Flag
    assert config.flag.startswith(b"CTF{")
    assert config.flag.endswith(b"}")
    enc_flag = bytes_to_long(config.flag)
    assert enc_flag < n

    # Encrypt Flag
    _enc = pow(enc_flag, config.e, n)


    with open ("flag.txt", "wb") as flag_file:
        flag_file.write(_enc.to_bytes(n.bit_length(), "little"))

    # Export RSA Key
    rsa = RSA.construct((n, config.e))
    with open ("public.pem", "w") as pub_file:
        pub_file.write(rsa.exportKey().decode())