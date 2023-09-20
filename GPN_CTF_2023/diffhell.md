# diffHell
- Category: Crypto
- Points: 526
> Welcome to Dr. Meta's Office. Leading villan since 1980. Due to some construction issues there is some information leaking... But rest be assured, to secure his evil plans Dr. Meta has refurbished Cryptography to secure his secrets. Sadly Dr. Meta has lost his keys after gluing himself to an exmatriculation form and his keys to the table below... With his exmatriculation in his hand and his keys on the table can you help out Dr. Meta and decrypt his important data? \
> `ncat --ssl diffhell-0.chals.kitctf.de 1337`

## Challenge source
```py
import hashlib
FLAG = b"GPNCTF{fake_flag}"
def genCommMat(M): 
    u = M[0][0]
    v = M[0][1]
    x = M[1][0]
    y = M[1][1]
    a = M.base_ring().random_element()
    b = M.base_ring().random_element()
    R = M.base_ring()
    c = b*x * v^-1
    d = (a*v + b*y - b*u)*v^-1
    return Matrix(R,[[a,b],[c,d]])

def genGLM(K):
    a,b,c,d = [K.random_element() for _ in [0,0,0,0]]
    M = Matrix(K,[[a,b],[c,d]])
    return M if M.rank() == 2 else genGLM(K)


#starting flag transmission
p = random_prime(2**41,2**42)
A = GL(2,GF(p)).random_element().matrix()
B = genCommMat(A)
G = GL(2,GF(p)).random_element().matrix()
print("Welcome to Dr. Meta's Office. Leading villan since 1980")
print(p)
print("Due to some construction issues there is some information leaking")
print("But rest be assured, to secure his evil plans Dr. Meta has refurbished Cryptography to secure his secrets")
print("Sadly Dr. Meta has lost his keys after gluing himself to an exmatriculation form and his keys to the table below... With his exmatriculation in his hand and his keys on the table can you help out Dr. Meta and decrypt his important data?")


print(G)
print("Look something has fallen from the back of the Turing machine")
print(A^-1*G*A)
gA   = A^-1 * G * A
gB = B ^-1 * G * B 
print("Look we found this on a stack of 'rubbish'")
print(gB)


super_secret_key = B^-1*gA*B
if super_secret_key != A^-1*gB * A :
    print("OHH nooo a MIMA X blew up. The plans to take over the world are destoryed.")

m = hashlib.sha256()
m.update(f"{super_secret_key[0][1]}{super_secret_key[1][0]}{super_secret_key[1][1]}{super_secret_key[0][0]}".encode())
otp = m.digest()
print("Here gulasch spice mix formula to take over the GPN ")
encMsg = [fl^^ot for fl,ot in zip(FLAG,otp)]
print(encMsg)
```

## Solution steps

### The scouting
Looking at the source code, we see we are dealing with a key exchange protocol over some matrix group. The private key `A` and public parameter `G` get picked randombly, then `B` is constructed from `A` by a function which would suggest something is going to start commuting, and indeed we see that `AB = BA` for all pairs of `A,B` generated this way.

Then we are given `G`, `gA   = A^-1 * G * A` and `gB = B^-1 * G * B`, before the protocol is simulated to get a shared secret `super_secret_key = B^-1 * gA * B = A^-1 * gB * A`, then we use this shared secret to derive an OTP key with which the flag gets encrypted and given to us.

### The math
Seems pretty clear, given that `B` depends on `A`, surely we can use those relations to compute the shared secret with the given values. We try putting together systems of equations and try to make Groebner help us, but for some reason it doesn't work. We messed something up, we try debugging and running it a few times to see if we got unlucky. But then...

### The realization
Seeing multiple outputs of the server, we notice something strange:
```Welcome to Dr. Meta's Office. Leading villan since 1980
194117207209
Due to some construction issues there is some information leaking
But rest be assured, to secure his evil plans Dr. Meta has refurbished Cryptography to secure his secrets
Sadly Dr. Meta has lost his keys after gluing himself to an exmatriculation form and his keys to the table below... With his exmatriculation in his hand and his keys on the table can you help out Dr. Meta and decrypt his important data?
[79505364158 98997595995]
[11750748731 86562273029]
```
```
Welcome to Dr. Meta's Office. Leading villan since 1980
505383308627
Due to some construction issues there is some information leaking
But rest be assured, to secure his evil plans Dr. Meta has refurbished Cryptography to secure his secrets
Sadly Dr. Meta has lost his keys after gluing himself to an exmatriculation form and his keys to the table below... With his exmatriculation in his hand and his keys on the table can you help out Dr. Meta and decrypt his important data?
[ 79505364158  98997595995]
[485523751128 286628655675]
```
Why are some values of `G` repeating? Isn't it supposed to be random. WTF is sage doing with this poor thing to have so little entropy. We run it a few more times and we notice the values of this matrix have very few posibilities. Since `A` is initialized the same way, it probably behaves the same way. Some local testing confirms our suspicion. We now have very few possible values for `A`, and looking at what we are given for `G` we should be able to determine which one to use. How nice, we can cheese this, no need for math.

### The cheese
At this point we got lazy, if we are cheesing the chall, let's cheese it completely. Instead of getting `A` seeing `G`, we just hardcode one of the `A` values output locally and run it repeatedly against the remote until it matches up, at that point the flag will decrypt correctly and we will be done.

### Solution script
```py
from pwn import *

context.log_level = "error"
A_ = [[1001014644478, 1663927207912], [1190180555211, 707604930676]]

while True:
    io = remote("diffhell-0.chals.kitctf.de", 1337, ssl=True)
    io.recvline()

    p = int(io.recvline())

    io.recvuntil(b"data?\n")

    G = []
    G.append(list(map(int, io.recvline().strip()[1:-1].split())))
    G.append(list(map(int, io.recvline().strip()[1:-1].split())))
    G = matrix(GF(p), G)

    io.recvline()

    gA = []
    gA.append(list(map(int, io.recvline().strip()[1:-1].split())))
    gA.append(list(map(int, io.recvline().strip()[1:-1].split())))
    gA = matrix(GF(p), gA)

    io.recvline()

    gB = []
    gB.append(list(map(int, io.recvline().strip()[1:-1].split())))
    gB.append(list(map(int, io.recvline().strip()[1:-1].split())))
    gB = matrix(GF(p), gB)

    A = matrix(GF(p), A_)

    super_secret_key = A^-1*gB * A

    m = hashlib.sha256()
    m.update(f"{super_secret_key[0][1]}{super_secret_key[1][0]}{super_secret_key[1][1]}{super_secret_key[0][0]}".encode())
    otp = m.digest()

    io.recvline()

    ct = bytes(map(int, io.recvline().strip()[1:-1].split(b", ")))
    flag = bytes([fl^^ot for fl,ot in zip(ct,otp)])
    if b"GPNCTF" in flag:
        print(flag)
        exit()

    io.close()
```

### Flag
> `GPNCTF{Dr.M3t4F0rTh3W1n!?0x1337}`