
### Challenge source
```py
from Crypto.Util.number import bytes_to_long as b2l
from Crypto.Util.number import long_to_bytes as l2b
import random

Zx.<x> = ZZ[]
def convolution(f,g):
  return (f * g) % (x^n-1)

def balancedmod(f,q):
  g = list(((f[i] + q//2) % q) - q//2 for i in range(n))
  return Zx(g)  % (x^n-1)

def randomdpoly(d1, d2):
  result = d1*[1]+d2*[-1]+(n-d1-d2)*[0]
  random.shuffle(result)
  return Zx(result)

def invertmodprime(f,p):
  T = Zx.change_ring(Integers(p)).quotient(x^n-1)
  return Zx(lift(1 / T(f)))

def invertmodpowerof2(f,q):
  assert q.is_power_of(2)
  g = invertmodprime(f,2)
  while True:
    r = balancedmod(convolution(g,f),q)
    if r == 1: return g
    g = balancedmod(convolution(g,2 - r),q)

def keypair():
  while True:
    try:
      f = randomdpoly(61, 60)
      f3 = invertmodprime(f,3)
      fq = invertmodpowerof2(f,q)
      break
    except Exception as e:
      pass
  g = randomdpoly(20, 20)
  publickey = balancedmod(3 * convolution(fq,g),q)
  secretkey = f
  return publickey, secretkey, g

def encode(val):
    poly = 0
    for i in range(n):
        poly += ((val%3)-1) * (x^i)
        val //= 3
    return poly

def encrypt(message, publickey):
  r = randomdpoly(18, 18)
  return balancedmod(convolution(publickey,r) + encode(message), q)


n, q = 263, 128
publickey, _, _ = keypair()

flag = open('flag', 'rb').read()
print(publickey)

for i in range(24):
    print(encrypt(b2l(flag), publickey))
```

### Analysis
We see that the challenge is just a regular implementation of NTRU. At first we thought the `randomdpoly` function was suspicious with setting the number of $-1$ and $1$ coefficients in the polynomial to be the same, but turns out that is normal behavior in the NTRU-1998 variant.

The next thing we noticed is that the script encrypts the flag with the same key 24 times. So the only difference between encryptions is the random polynomial $r$. We searched for key reuse attacks against NTRU and found the following paper: https://ntru.org/f/tr/tr006v1.pdf and it turns out this is exactly what we need. 

The attacks abuses the fact than in a NTRU encryption

$$
e_i = r_i*h +m
$$

for message $m$ and public key $h$. We then compute

$$ 
c_i = (e_i-e_1)*h^{-1} = r_i - r_1
$$

Since the coefficients of $r_i$ are elements of $\{-1,0,1\}$, we know that each coefficient of $c_i$ will be in $\{-2,-1,0,1,2\}$, and each non zero value gives us some information about $r_i$. With this we can recover most of $r_1$, we then repeat this for all $r_i$.

We did not recover some information that we could have in this step, as $h$ is not invertible, because it shares a common factor $x-1$ with the polynomial modulo which we were working on. We found a workaround to this by computing the division in rationals and then casting the result back to our field. This worked most of the time, since $e_i - e_j$ had $x-1$ as a factor most of the time as well. In other cases we discarded that information. When solving the other NTRU challenge **everywhere**, we found out we could have used a pseudoinverse in this place instead.

Then we reduce the options by comparing $(e_i - e_j)*h^{-1}$ to $r_i - r_j$ that we got. Since we know most of the coefficients of $r_i$ and $r_j$, we can now determine the potentially unknown coefficients of the other one. With this we know nearly all the coefficients of all $r_i$, and we can iterate over all possible options to try and decrypt the message the following way:

$$
m = e_i - r_i*h
$$

This gets us the flag `hitcon{mu1tip13_encrypt1on_no_Encrpyti0n!}`

### Implementation
```py
from Crypto.Util.number import long_to_bytes as l2b
from itertools import product

P.<y> = QQ[]
n, q = 263, 128
R.<x> = P.quotient(y^n - 1)

f = open("output.txt").readlines()

h = R(eval(f[0].replace("^", "**")))
cts = []

for ct in f[1:]:
    cts.append(R(eval(ct.replace("^", "**"))))

all_pos = {}
all_coefs = {}
constraints = {-2: {-1}, -1: {-1, 0}, 0: {-1, 0, 1}, 1: {0, 1}, 2: {1}}

for e0 in cts:
    possible = [{-1,0,1} for _ in range(n)]
    for e1 in cts:
        if e0 == e1: continue

        ci_QQ = (e0 - e1) / h
        try:
            coefs = [ci_QQ[i] % q for i in range(n)]
        except:
            continue

        sc = set(coefs)
        if len(sc) > 5: 
            continue
        sor = sorted(list(sc))
        if len(sor) < 5:
            for i in range(len(sor)): 
                if sor.count(sor[i]) >= 199:
                    for _ in range(i,2): sor = [None] + sor
                    break
            while len(sor) < 5: sor = sor + [None]
        mapping = {k: v for k,v in zip(sor, [-2,-1,0,1,2])}

        coefs = [mapping[c] for c in coefs]
        if set(coefs) <= {0, 1, 2, -2, -1} and coefs.count(0) >= 199:
            all_coefs[(e0,e1)] = coefs
            for i in range(n):
                possible[i] &= constraints[coefs[i]]

    all_pos[e0] = [{0} if p == {-1,0,1} else p for p in possible]

for e0 in cts:
    for e1 in cts:
        if (e0,e1) not in all_coefs: continue
        coefs = all_coefs[(e0,e1)]

        for i in range(n):
            c0 = all_pos[e0][i]
            c1 = all_pos[e1][i]
            s = coefs[i]
            if len(c0) == 1 and len(c1) == 2:
                all_pos[e1][i] = {list(c0)[0] - s}
            if len(c0) == 2 and len(c1) == 1:
                all_pos[e0][i] = {list(c1)[0] + s}
            if len(c0) == 2 and len(c1) == 2 and s == 0 and c0 != c1:
                all_pos[e0][i] = {0}
                all_pos[e1][i] = {0}

for ct, pos in all_pos.items():
    for p in product(*pos):
        if p.count(-1) != 18 or p.count(1) != 18: continue
        r = R(list(p))

        m = ct - r*h
        val = 0
        for i in range(n):
            c = (m[i] + 1) % q
            val += int(c)*3^i

        pt = l2b(val)
        if b"hitcon{" in pt:
            print(pt)
            exit()
```