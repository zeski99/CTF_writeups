#### Description
How careless can you be as an assistant...

`nc chal-careless-padding.chal.hitconctf.com 11111`


#### Challenge source code
```py
#!/usr/local/bin/python
import random
import os
from secret import flag
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import json

N = 16

# 0 -> 0, 1~N -> 1, (N+1)~(2N) -> 2 ...
def count_blocks(length):
    block_count = (length-1) // N + 1
    return block_count

def find_repeat_tail(message):
    Y = message[-1]
    message_len = len(message)
    for i in range(len(message)-1, -1, -1):
        if message[i] != Y:
            X = message[i]
            message_len = i + 1
            break
    return message_len, X, Y

def my_padding(message):
    message_len = len(message)
    block_count = count_blocks(message_len)
    result_len =  block_count * N
    if message_len % N == 0:
        result_len += N
    X = message[-1]
    Y = message[(block_count-2)*N+(X%N)]
    if X==Y:
        Y = Y^1
    padded = message.ljust(result_len, bytes([Y]))
    return padded

def my_unpad(message):
    message_len, X, Y = find_repeat_tail(message)
    block_count = count_blocks(message_len)
    _Y = message[(block_count-2)*N+(X%N)]
    if (Y != _Y and Y != _Y^1):
        raise ValueError("Incorrect Padding")
    return message[:message_len]

def chal():
    k = os.urandom(16)
    m = json.dumps({'key':flag}).encode()

    iv = os.urandom(16)
    cipher = AES.new(k, AES.MODE_CBC, iv)

    padded = my_padding(m)
    enc = cipher.encrypt(padded)
    print(f"""
*********************************************************
You are put into the careless prison and trying to escape.
Thanksfully, someone forged a key for you, but seems like it's encrypted... 
Fortunately they also leave you a copied (and apparently alive) prison door.
The replica pairs with this encrypted key. Wait, how are this suppose to help?
Anyway, here's your encrypted key: {(iv+enc).hex()}
*********************************************************
""")

    while True:
        enc = input("Try unlock:")
        enc = bytes.fromhex(enc)
        iv = enc[:16]
        cipher = AES.new(k, AES.MODE_CBC, iv)
        try:
            message = my_unpad(cipher.decrypt(enc[16:]))
            if message == m:
                print("Hey you unlock me! At least you know how to use the key")
            else:
                print("Bad key... do you even try?")
        except ValueError:
            print("Don't put that weirdo in me!")
        except Exception:
            print("What? Are you trying to unlock me with a lock pick?")

if __name__ == "__main__":
    chal()
```
#### Solution steps
We can see this is just using CBC mode with some custom padding. Looks very broken from the start, but works in a slightly wierd way, so we have to recover the plaintext in multiple steps.


First let's have some setup:
```py
from pwn import *
from string import printable

pool = printable.encode()

io = remote("chal-careless-padding.chal.hitconctf.com", 11111)

io.recvuntil(b"key: ")

CT = unhex(io.recvline())

def query(ct):
    io.sendlineafter(b"Try unlock:", ct.hex().encode())
    r = io.recvline().strip()
    if r == b"What? Are you trying to unlock me with a lock pick?":
        return "WIN"
    return r != b"Don't put that weirdo in me!"

for I in range(0, len(CT)-16, 16):
```
First we want to recover the lower 4 bits of `X`. Those work as an index pointing to the character which gets compared to `Y`. Running it twice, the only value that occurs twice is the one where `X` in the plaintext points at `Y` specifically.
```py
    s = [set(), set()]
    for i in range(2):
        for X in range(16):
            mask = bytes([i*0xff]*14 + [0xf0 ^ X] + [0])
            if query(xor(CT[0+I:16+I], mask) + CT[16+I:32+I]):
                s[i].add(X)

    X = set.intersection(*s).pop()
```
Next loop over the first 14 bytes, poining `X` at each one and brute forcing until the padding is correct. When that happens, we know the value of that byte in plaintext is the same as the value of the last bytes in the block.
```py
    s = [set() for _ in range(14)]

    for i in range(14):
        for v in range(0, 256, 2):
            mask = bytes([0]*i + [v] + [0]*(13-i) + [X ^ 0xf ^ i] + [0])
            assert len(mask) == 16
            if query(xor(CT[0+I:16+I], mask) + CT[16+I:32+I]):
                s[i].add(v)
                break

    rels = [ss.pop() & 0xfe for ss in s] + [X ^ 0xf,0]

```
Next we recover the relation between the last 2 bytes in a similar manner.
```py
    s = set()

    for v in range(256):
        mask = rels[:]
        mask[-2] = X ^ 1
        mask[-1] = v
        if query(xor(CT[0+I:16+I], mask) + CT[16+I:32+I]):
            s.add(v)
            break

    rels[-2] = (s.pop() & 0xfe) ^ X

    rels = xor(rels, rels[-2])
    rels = list(xor(rels, X ^ 0xf))

```
Now `rels` is such an array that when xor-ed with the iv, the plaintext will be composed of all the same values, only possibly differing in the least significant bit. Next we recover the relations between the lsb of each byte.
```py

    mask = xor(rels, [0] + [0x3]*13 + [0] + [0])
    if query(xor(CT[0+I:16+I], mask) + CT[16+I:32+I]):
        rels[-1] ^= 1

    for i in range(13, 1, -1):
        mask1 = xor(rels, [0,0xff] + [0xf]*(i-2) + [0]*(16-i))
        mask2 = xor(rels, [0,0xff] + [0xf]*(i-2) +[1] + [0]*(16-i-1))
        if not query(xor(CT[0+I:16+I], mask1) + CT[16+I:32+I]) and query(xor(CT[0+I:16+I], mask2) + CT[16+I:32+I]):
            rels[i] ^= 1

    mask = rels[:]
    mask[1] ^= 0xf0

    if not query(xor(CT[0+I:16+I], mask) + CT[16+I:32+I]):
        rels[1] ^= 1

    if query(xor(CT[0+I:16+I], rels) + CT[16+I:32+I]) != "WIN":
        rels[0] ^= 1

```
Now we know the relation between the bytes, and additionally know the lower 4 bits of the second to last byte. All that remains is to brute the upper 4 bits and check which plaintexts are printable and look like they belong to the flag.
```py
    for i in range(16):
        cand = xor(rels, i << 4)
        if all(c in pool for c in cand):
            print(I, cand)
```
`hitcon{p4dd1ng_w0n7_s4v3_y0u_Fr0m_4_0rac13_617aa68c06d7ab91f57d1969e8e8532}`
