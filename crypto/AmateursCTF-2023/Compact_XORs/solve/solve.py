fleg = '610c6115651072014317463d73127613732c73036102653a6217742b701c61086e1a651d742b69075f2f6c0d69075f2c690e681c5f673604650364023944'
for i in range(len(fleg)//4):
    print(chr(int(fleg[i*4:i*4+2],16)),end='')
    print(chr(int(fleg[i*4:i*4+2], 16) ^ int(fleg[i*4+2:i*4+4], 16)), end='')

