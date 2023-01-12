### IS_THIS_LCG

Looking at the code we see the code generates 3 random primes each with a different RNG, then another safe prime, than encrypts with this multiprime RSA. So we have to recover each factor to decrypt.

#### Part 1
We have a truncated output LCG, standard stuff we have done before, but we just copied the solve from some old repo, so we don't actually have to implement stuff.
https://github.com/jvdsn/crypto-attacks/blob/master/attacks/lcg/truncated_state_recovery.py

#### Part 2
Thanks [Jack](https://github.com/jack4818) for doing most of the work on this part.
For this part we have some LCG looking thing over a random elliptic curve, and we need to find the prime this curve is over, only given some x coordinates. With some pen and paper magic we got some equations that let us do that and then compute p. In short: Taking linear combinations of points, we deduce a set of polynomial equations by working with the formula for point addition on elliptic curves. Given enough equations, we can remove all unknowns to be left with an integer which will be a multiple of p. We can recover the prime p by taking the gcd with the modulus n. You can find a more detailed explanation here: https://hackmd.io/@jack4818/SJjuNt4di

```python=
R.<A, B> = ZZ[]

def ysqr(x):
    return x^3 + A*x + B

def f(x1, x2, x3):
    """
    λ_22^2 - 2x2 + x1 + x3)(x3 - x1)^2 - y1^2 - y3^2 = -2y1y3
    """
    l22sqr = (3*x2^2 + A)^2 / (4*ysqr(x2))
    lhs = l22sqr - 2*x2 + x1 + x3
    lhs *= (x3 - x1)^2
    lhs -= (ysqr(x1) + ysqr(x3))
    return lhs

def g(x1, x3, minus_2y1y3):
    """
    P1 - P3
    """
    return ((ysqr(x3) - minus_2y1y3 + ysqr(x1)) / (x3 - x1)^2) - x1 - x3

def h(x1, x2, x3, x4, minus_2y1y3, minus_2y2y4):
    P1P3 = g(x1, x3, minus_2y1y3)
    P2P4 = g(x2, x4, minus_2y2y4)
    return P1P3 - P2P4

def gen_poly(x1, x2, x3, x4):
    minus_2y1y3 = f(x1, x2, x3)
    minus_2y2y4 = f(x2, x3, x4)
    return h(x1, x2, x3, x4, minus_2y1y3, minus_2y2y4)

def gen_poly_numerator(x1, x2, x3, x4):
    p = gen_poly(x1, x2, x3, x4)
    return p.numerator()

from sage.matrix.matrix2 import Matrix 
def resultant(f1, f2, var):
    return Matrix.determinant(f1.sylvester_matrix(f2, var))

def get_multiple(x1, x2, x3, x4, x5, x6):
    p1 = gen_poly_numerator(x1, x2, x3, x4)
    p2 = gen_poly_numerator(x2, x3, x4, x5)
    p3 = gen_poly_numerator(x3, x4, x5, x6)

    remove_b1 = resultant(p1, p2, B)
    remove_b2 = resultant(p1, p3, B)
    remove_a = resultant(remove_b1, remove_b2, A)

    return remove_a

kp1 = get_multiple(x1, x2, x3, x4, x5, x6)

print(gcd(kp1, N))
```

#### Part 3
We are given a kind of LCG, but instead done over matrices. Since we have a lot of outputs, and the matrices are not very big, we can solve this by just making A and B symbolic to get a system of equations and solve for A,B. Then we get a close formula to get $X_i = A^iX_0 + (A^i - I)/(A - I)*B$ and use that to compute the output we want.

```python=
n, m = 8, next_prime(2^16)

def mt2dec(X):
    x = 0
    for i in range(n):
        for j in range(n):
            x = x + int(X[i, j]) * (m ** (i * n + j))
    return x

def dec2mt(x):
    X = matrix(GF(m), n, n)
    for i in range(n):
        for j in range(n):
            X[i,j] = x % m
            x = x // m
    return X

P = PolynomialRing(GF(m), 128, "x")

g = P.gens()

A = matrix(P, [[g[i + 8*j] for i in range(8)] for j in range(8)])
B = matrix(P, [[g[i + 8*j + 64] for i in range(8)] for j in range(8)])

eqs = []
res = []

def add_eqs(eqs, X0, X1):
    E = A*dec2mt(X0) + B
    R = dec2mt(X1)
    for i in range(8):
        for j in range(8):
            eqs.append(E[i,j])
            res.append(R[i,j])

add_eqs(eqs, X0, X1)
add_eqs(eqs, X1, X2)
add_eqs(eqs, X2, X3)
add_eqs(eqs, X3, X4)
add_eqs(eqs, X4, X5)
add_eqs(eqs, X5, X6)
add_eqs(eqs, X6, X7)
add_eqs(eqs, X7, X8)
add_eqs(eqs, X8, X9)

mat = []

for eq in eqs:
    mat.append([eq.coefficient(g[i]) for i in range(128)])

vec = vector(GF(m), res)
mat = matrix(GF(m), mat)

ab = mat \ vec

A = matrix(GF(m), [[ab[i + 8*j] for i in range(8)] for j in range(8)])
B = matrix(GF(m), [[ab[i + 8*j + 64] for i in range(8)] for j in range(8)])

X = dec2mt(X0)

I = identity_matrix(GF(m), 8)

AA = A^(1337**1337)
BB = (AA - I)/(A - I)*B

Y = AA*X + BB

p3 = next_prime(mt2dec(Y))
```

Now all that is left is to decrypt the flag.
```python=
q = N // p1 // p2 // p3

e = 0x10001

phi = (p1-1)*(p2-1)*(p3-1)*(q-1)
d = pow(e, -1, phi)

m = pow(c, d, N)

print(long_to_bytes(int(m)))
```
`RCTF{Wo0oOoo0Oo0W_LCG_masT3r}`