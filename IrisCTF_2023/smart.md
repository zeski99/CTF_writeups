## SMarT 1 and 2

We are given the following source code:

```py
from pwn import xor

# I don't know how to make a good substitution box so I'll refer to AES. This way I'm not actually rolling my own crypto
SBOX = [99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22]

TRANSPOSE = [[3, 1, 4, 5, 6, 7, 0, 2],
 [1, 5, 7, 3, 0, 6, 2, 4],
 [2, 7, 5, 4, 0, 6, 1, 3],
 [2, 0, 1, 6, 4, 3, 5, 7],
 [6, 5, 0, 3, 2, 4, 1, 7],
 [2, 0, 6, 1, 5, 7, 4, 3],
 [1, 6, 2, 5, 0, 7, 4, 3],
 [4, 5, 6, 1, 2, 3, 7, 0]]

RR = [4, 2, 0, 6, 9, 3, 5, 7]
def rr(c, n):
    n = n % 8
    return ((c << (8 - n)) | (c >> n)) & 0xff

import secrets
ROUNDS = 2
MASK = secrets.token_bytes(8)
KEYLEN = 4 + ROUNDS * 4
def encrypt(block, key):
    assert len(block) == 8
    assert len(key) == KEYLEN
    block = bytearray(block)

    for r in range(ROUNDS):
        block = bytearray(xor(block, key[r*4:(r+2)*4]))
        for i in range(8):
            block[i] = SBOX[block[i]]
            block[i] = rr(block[i], RR[i])

        temp = bytearray(8)
        for i in range(8):
            for j in range(8):
                temp[j] |= ((block[i] >> TRANSPOSE[i][j]) & 1) << i

        block = temp

        block = xor(block, MASK)
    return block

def ecb(pt, key):
    if len(pt) % 8 != 0:
        pt = pt.ljust(len(pt) + (8 - len(pt) % 8), b"\x00")

    out = b""
    for i in range(0, len(pt), 8):
        out += encrypt(pt[i:i+8], key)
    return out

key = secrets.token_bytes(KEYLEN)
FLAG = b"irisctf{redacted}"
print(f"MASK: {MASK.hex()}")
print(f"key: {key.hex()}")
import json
pairs = []
for i in range(8):
    pt = secrets.token_bytes(8)
    pairs.append([pt.hex(), encrypt(pt, key).hex()])
print(f"some test pairs: {json.dumps(pairs)}")
print(f"flag: {ecb(FLAG, key).hex()}")
```

For the first part of the challenge, we are given the key, so all we need to do is figure out how to decrypt, given the encryption algorithm.

For the second part, we are not given the key, so we need to figure out a way to find the key or decrypt using the 8 pairs of plaintexts and ciphertexts we are given.
After a quick look at the source code, i noticed that the encryption is only using 2 rounds, which is way too little. Then everything apart from the step using `SBOX`, everything is linear, so we can use z3 on those parts. But since z3 doesn't work well with SBOXes, we first simplify the constraints it's going to need to solve by partially decrypting the ciphertext, stoping at the first swap bytes operation. From the other side we also partially encrypt until we get to that point, which is a single xor with the round key. This leaves us with the following:

$$
\text{SBOX}[\text{xor}(\text{pt}, \text{key})] = \text{partial\_dec}(\text{ct})
$$

Which allows us too look for such keys, where for all (plaintext, ciphertext) pairs, there exists a $0 \leq i < 256$ such that 

$$
i = \text{xor}(\text{pt}, \text{key})
$$

and

$$
\text{SBOX}[i] = \text{partial\\_dec}(\text{ct})
$$

Putting these constraints in z3 gives us the key.

### Solution script
```py
from pwn import unhex
from z3 import *

def xor(a,b):
    return [x^y for x,y in zip(a,b)]

SBOX = [99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22]
I_SBOX = [SBOX.index(i) for i in range(256)]

TRANSPOSE = [[3, 1, 4, 5, 6, 7, 0, 2],
 [1, 5, 7, 3, 0, 6, 2, 4],
 [2, 7, 5, 4, 0, 6, 1, 3],
 [2, 0, 1, 6, 4, 3, 5, 7],
 [6, 5, 0, 3, 2, 4, 1, 7],
 [2, 0, 6, 1, 5, 7, 4, 3],
 [1, 6, 2, 5, 0, 7, 4, 3],
 [4, 5, 6, 1, 2, 3, 7, 0]]
RR = [4, 2, 0, 6, 9, 3, 5, 7]
ROUNDS = 2
KEYLEN = 4 + ROUNDS * 4

def rr_i_z3(c,n):
    n = n % 8
    return (LShR(c, (8 - n)) | (c << n)) & 0xff

def i_rot_z3(block):
    for i in range(8):
        block[i] = rr_i_z3(block[i], RR[i])
    return block

def i_diffuse_z3(block):
    temp = [BitVecVal(0,8) for _ in range(8)]
    for i in range(8):
        for j in range(8):
            temp[i] |= (LShR(block[j], i) & 1) << TRANSPOSE[i][j]
    return temp

def rr_i(c,n):
    n = n % 8
    return ((c >> (8 - n)) | (c << n)) & 0xff

def i_sb_rr(block):
    for i in range(8):
        block[i] = rr_i(block[i], RR[i])
        block[i] = I_SBOX[block[i]]
    return block

def i_diffuse(block):
    temp = [0 for _ in range(8)]
    for i in range(8):
        for j in range(8):
            temp[i] |= ((block[j] >> i) & 1) << TRANSPOSE[i][j]
    return temp

def decrypt(block, key):
    assert len(block) == 8
    assert len(key) == KEYLEN
    block = block

    for r in range(ROUNDS-1,-1,-1):
        block = xor(block, MASK)
        block = i_diffuse(block)
        block = i_sb_rr(block)
        block = xor(block, key[r*4:(r+2)*4])

    return block

def dec(ct, key):
    out = []
    for i in range(0, len(ct), 8):
        out += decrypt(ct[i:i+8], key)
    return out

# PART 1:
MASK = unhex("3d5e286c30e3af35")
key = unhex("bc62c0b71ac3ebb55c01ca09")
pairs = [["e5557fc33c21464d", "93ae80b638ec489f"], ["f651d04314a88dfd", "fdf9524bacd3c612"], ["c6f70ae9b42a6d60", "256a9be8ae07be30"], ["6a9ee1d831a15dfd", "b19a9af0242733d1"], ["f3aa021a7fe92f1f", "ca8042945983a704"], ["d38ab4b2384ab779", "34a0b40fc7098d4d"], ["d989f5c89ce3d904", "2be0785e9742934f"], ["a22bb47739fd561a", "1aab6e73f113a38f"]]
flag = unhex("efb6d7f1a2ddefdd04567cedb6d2a6c5fa8b96ad26f92fb1b0b55ad6a13838c6")
print(bytes(dec(flag, key)))

MASK = unhex("1f983a40c3f801b1")
pairs = [["4b0c569de9bf6510", "3298255d5314ad33"], ["5d81105912c7f421", "805146efee62f09f"], ["6e23f94180be2378", "207a88ced8ab64d1"], ["9751eeee344a8c74", "0b561354ebbb50fa"], ["f4fbf94509aaea25", "4ba4dc46bbde5c63"], ["3e571e4e9604769e", "10820c181de8c1df"], ["1f7b64083d9121e8", "0523ce32dd7a9f02"], ["69b3dfd8765d4267", "23c8d59a34553207"]]
flag = unhex("ceb51064c084e640690c31bf55c1df4950bc81b484f559dce0ae7d509aa0fe07f7ee127e9ecb05eb4b1b58b99494f72c0b4f3f5fe351c1cb")

def partial_dec(block, key):
    block = xor(block, MASK)
    block = i_diffuse(block)
    block = i_sb_rr(block)
    block = xor(block, key[4:12])
    block = xor(block, MASK)
    block = i_diffuse_z3(block)
    block = i_rot_z3(block)
    return block

s = Solver()
key = [BitVec(f"k{i}", 8) for i in range(12)]

for pair in pairs:
    pct = partial_dec(unhex(pair[1]), key)
    ppt = [a ^ b for a,b in zip(unhex(pair[0]), key[:12])]
    for b,a in zip(pct, ppt):
        s.add(Or(*[And(a == i, b == SBOX[i]) for i in range(256)]))

if s.check() == sat:
    KEY = bytes([s.model()[k].as_long() for k in key])
    print(bytes(dec(flag, KEY)))
```
`irisctf{ok_at_least_it_works}`
`irisctf{if_you_didnt_use_a_smt_solver_thats_cool_too}`
