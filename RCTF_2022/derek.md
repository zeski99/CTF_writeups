### Derek

After a quick look at the code we see we are dealing with a feistel network with a lot of rounds. Next we notice the round function is using aes with a random key we don't know much about, so it is unlikely we break that part. What we can do however is make sure the following ends up in `t=0`:
```python=
t = aes(int(t.hex(), 16), self.keys[i]) & 0xffffffffffffffff
t ^= aes(0xdeadbeefbaadf00d if i % 2 else 0xbaadf00ddeadbeef,
         self.keys[i]) & 0xffffffffffffffff
```
This would mean we need to give it something that will equal the constant values we see here after the loop including some magic. Since we are too lazy to actually reverse what that loop does, we first tried if we can brute it, and it turns out a byte by byte brute force works. 

```python=
def magic(l):
    magic = c_uint64(0xffffffffffffffff)
    for m in bytes([int(bin(byte)[2::].zfill(8)[8::-1], 2)
                    for byte in l.to_bytes(8, 'big')]):
        magic.value ^= c_uint64(m << 56).value
        # print(hex(magic.value)[2:].zfill(16))
        for j in range(8):
            if magic.value & 0x8000000000000000 != 0:
                magic.value = magic.value << 1 ^ 0x1b
            else:
                magic.value = magic.value << 1
        # print(hex(magic.value)[2:].zfill(16))
    magic.value ^= 0xffffffffffffffff
    t = bytes([int(bin(byte)[2::].zfill(8)[8::-1], 2)
                for byte in bytes(magic)])
    return t

t = "baadf00ddeadbeef" # 0x383972b703bd8d98
t = "deadbeefbaadf00d" # 0xd80be0534925b5d6

known = [[]]

for i in range(8):
    new = []
    for K in known:
        N = 0
        for n in K:
            N = (N << 8) + n

        for n in range(256):
            num = (N << 8*(8-i)) + (n << 8*(7-i))
            if magic(num).hex()[-2*i-1:] == t[-2*i-1:]:
                new.append(K + [n])
    known = new

for K in known:
    N = 0
    for n in K:
        N = (N << 8) + n
    if magic(N).hex() == t:
        print(hex(N))
```

With this we have the inputs that will make the feistel network just swap l,r over and over, instead of actually encrypting them. After the last round they are then xor-ed with the key, and so by encrypting this known plaintext we can recover the key and decrypt the flag.

```python=
from Crypto.Util.number import *
from ctypes import c_uint64
from util import aes, nsplit
from Crypto.Util.Padding import unpad
from Derek import Derek
from pwn import *

class DecryptingDerek(Derek):
    def enc_block(self, x: int) -> int:
        x_bin = bin(x)[2:].rjust(128, '0')
        l, r = int(x_bin[:64], 2), int(x_bin[64:], 2)
        for i in range(self.rnd):
            magic = c_uint64(0xffffffffffffffff)
            for m in bytes([int(bin(byte)[2::].zfill(8)[8::-1], 2)
                            for byte in l.to_bytes(8, 'big')]):
                magic.value ^= c_uint64(m << 56).value
                for j in range(8):
                    if magic.value & 0x8000000000000000 != 0:
                        magic.value = magic.value << 1 ^ 0x1b
                    else:
                        magic.value = magic.value << 1
            magic.value ^= 0xffffffffffffffff
            t = bytes([int(bin(byte)[2::].zfill(8)[8::-1], 2)
                      for byte in bytes(magic)])
            t = aes(int(t.hex(), 16), self.keys[i]) & 0xffffffffffffffff
            t ^= aes(0xdeadbeefbaadf00d if i % 2 else 0xbaadf00ddeadbeef,
                     self.keys[i]) & 0xffffffffffffffff
            l, r = r ^ t, l
        l ^= int.from_bytes(self.key[:8], 'big')
        r ^= int.from_bytes(self.key[8:], 'big')
        l, r = r, l
        y = (l + (r << 64)) & 0xffffffffffffffffffffffffffffffff
        return y

    def dec_block(self, y: int) -> int:
        U64_MAX = (1 <<64)-1
        r = (y >> 64) & U64_MAX
        l = y & U64_MAX
        l, r = r, l
        l ^= int.from_bytes(self.key[:8], 'big')
        r ^= int.from_bytes(self.key[8:], 'big')

        for i in reversed(range(self.rnd)):
            l, r = r, l
            magic = c_uint64(0xffffffffffffffff)
            for m in bytes([int(bin(byte)[2::].zfill(8)[8::-1], 2)
                            for byte in l.to_bytes(8, 'big')]):
                magic.value ^= c_uint64(m << 56).value
                for j in range(8):
                    if magic.value & 0x8000000000000000 != 0:
                        magic.value = magic.value << 1 ^ 0x1b
                    else:
                        magic.value = magic.value << 1
            magic.value ^= 0xffffffffffffffff
            t = bytes([int(bin(byte)[2::].zfill(8)[8::-1], 2)
                      for byte in bytes(magic)])
            t = aes(int(t.hex(), 16), self.keys[i]) & 0xffffffffffffffff
            t ^= aes(0xdeadbeefbaadf00d if i % 2 else 0xbaadf00ddeadbeef,
                     self.keys[i]) & 0xffffffffffffffff
            r ^= t

        x = l << 64 | r
        return x

    def decrypt(self, text: bytes) -> bytes:
        text_blocks = nsplit(text, 16)
        result = b''
        for block in text_blocks:
            block = int.from_bytes(block, 'big')
            result += self.dec_block(block).to_bytes(16, 'big')
        return unpad(result, 16)

a = 0x383972b703bd8d98
b = 0xd80be0534925b5d6
n = (a << 64) + b

io = remote("94.74.90.243", 42000)

io.sendlineafter(b"> ", b"E")
io.sendlineafter(b"> ", hex(n)[2:].encode())
ct = unhex(io.recvline())[:16]
key = xor(long_to_bytes(n), ct)


D = DecryptingDerek(key, rnd=42)

io.sendlineafter(b"> ", b"G")
fct = unhex(io.recvline())

print(D.decrypt(fct))
```

`RCTF{3asy_backd0or_wiTh_CRC_r3ver3s1ng}`