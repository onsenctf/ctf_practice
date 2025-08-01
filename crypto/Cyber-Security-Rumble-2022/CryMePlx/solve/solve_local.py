from pwn import *
import binascii


context.log_level = 'debug'
# flag = CSR{dummy_flag}

# enc_flag : 08fe7a37db94827ed7578ed82f9312
enc_flag = binascii.unhexlify(b'08fe7a37db94827ed7578ed82f9312')
print(enc_flag)

# AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA : 0aec690dfea0ae52ef49a9f50fb52e5dc3ee2777d49e74511354134cf4d1
input = 'A' * 30
enc_input = binascii.unhexlify(
    b'0aec690dfea0ae52ef49a9f50fb52e5dc3ee2777d49e74511354134cf4d1')

flag = xor(input, enc_input, enc_flag)
print(flag)
