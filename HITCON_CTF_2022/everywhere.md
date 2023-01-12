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
T = 400

flag = open('flag', 'rb').read()

for i in range(T):
    publickey, _, _ = keypair()
    print("key: ", publickey)
    print("data:", encrypt(b2l(flag), publickey))
```

### Analysis
We see the challenge source is almost the same as in the **Easy NTRU** challenge, it is implementing NTRU-1998 encryption. But instead of 24 encryptions with the same key, now we are given 400 encryptions, but each of them with a fresh key. This reminds us of the broadcast attack, and indeed when we search for such attacks agains NTRU we find the following paper: https://eprint.iacr.org/2011/590.pdf. We quickly realize this is exactly what we need.

The attack converts the polynomials used in NTRU into an equivalent matrix form, and then algebraically recovers the message. The first problem we run into is that the public key $h$ is not invettible, but we the peper describes how to get a pseudoinverse $h'$ such that $h'*h * r = r$, and that is sufficient for the attacks needs.

Then we want to convert our public key $h$ and its pesudoinverse $h'$ into a matrix, we do this the following way:

$$
H = \begin{bmatrix}
h_0 & h_{n-1} & \dots & h_1 \\
h_1 & h_0 & \dots & h_2 \\
\vdots & \vdots & \ddots & \vdots \\
h_{n-1} & h_{n-2} & \dots & h_0
\end{bmatrix}
$$

where 

$$
h = \sum_{i=0}^{n-1} h_ix^i
$$

is the public key. We get the pseudoinverse matrix $Ĥ$ the same way from $h'$. Other polynomials we write as vectors $f = (f_0, \dots, f_{n-1})$. All operations are done $\mod q$ unless stated otherwise.

Now we can represent NTRU encryption as

$$
c = Hr + m.
$$

We then multiply this by $Ĥ$ and denote $b = Ĥc$.

$$
\begin{align}
Ĥm + r & = b \nonumber \\
Ĥm - b & = r \nonumber\\
(Ĥm - b)^T(Ĥm - b) & = r^Tr \nonumber\\
b^Tb - 2b^TĤm + m^TĤ^TĤm & = r^Tr \nonumber\\
m^TĤ^TĤm - 2b^TĤm & = r^Tr - b^Tb \nonumber
\end{align}
$$

By lemma (2.2) described in the linked paper $Ĥ^TĤ$ is of the following form for some $a_i$.

$$
Ĥ^TĤ = \begin{bmatrix}
a_0 & a_{n-1} & \dots & a_1 \\
a_1 & a_0 & \dots & a_2 \\
\vdots & \vdots & \ddots & \vdots \\
a_{n-1} & a_{n-2} & \dots & a_0
\end{bmatrix}
$$

By the construction of $r$, the value $d = r^Tr$ is known to us, as it is exactly the number of non zero coefficients in $r$. We denote $s = d - b^Tb$ and  $b^TĤ = (w_0,w_1, \dots, w_{n-1})$ to get the following equation:

$$
m^TĤ^TĤm - 2(w_0,w_1, \dots, w_{n-1})m = s
$$

$$
\begin{align}
& a_0(m_0^2 + m_1^2 + \dots + m_{n-1}^2) \nonumber \\
& + a_1(m_1m_0 + m_2m_1 + \dots + m_0m_{n-1}) \nonumber \\
& + \dots \nonumber \\
& + a_{n-1}(m_{n-1}m_0 + m_0m_1 + \dots + m_{n-2}m_{n-1}) \nonumber \\
& - 2w_0m_0 - 2w_1m_1 - \dots - 2w_{n-1}m_{n-1} = s \nonumber \\
\end{align}
$$

Let $x_i = m_im_0 + m_{i+1}m_1 + \dots + m_{n-1}m_{n-i-1} + m_0m{n-i} + \dots + m_{i-1}m_{n-1}$. Note that $n$ is an odd prime, so $a_i = a_{n-i}, x_i = x_{n-i}$. Knowing this we end up with the following equation:

$$
a_0x_0 + 2a_1x_1 + \dots + 2a_{\lceil \frac{n}{2} \rceil}x_{\lceil \frac{n}{2} \rceil} - 2w_0m_0 - \dots - 2w_{n-1}m_{n-1} = s
$$

Now since $r(1) = 0$ and $h(1)r(1) + m(1) = c(1)$ it follows that $m(1) = c(1)$.

$$
\begin{align}
m_0 + \dots + m_{n-1} & = c(1) \nonumber \\
(m_0 + \dots + m_{n-1})^2 & = c(1)^2 \nonumber \\
x_0 + 2x_1 + \dots + 2x_{\lceil \frac{n}{2} \rceil} &= c(1)^2 \nonumber \\
c(1)^2 - 2x_1 - \dots - 2x_{\lceil \frac{n}{2} \rceil} &= x_0 \nonumber
\end{align}
$$

By plugging this in the equation above we get

$$
2(a_1 - a_0)x_1 + \dots + 2(a_{\lceil \frac{n}{2} \rceil} - a_0)x_{\lceil \frac{n}{2} \rceil} - 2w_0m_0 - \dots - 2w_{n-1}m_{n-1} = s - a_0c(1)^2 \mod q
$$

Since it turns out $s - a_0c(1)^2$ is divisible by $2$, we can divide the entire equation by $2$ to get

$$
(a_1 - a_0)x_1 + \dots + (a_{\lceil \frac{n}{2} \rceil} - a_0)x_{\lceil \frac{n}{2} \rceil} - w_0m_0 - \dots - w_{n-1}m_{n-1} = \frac{s - a_0c(1)^2}{2} \mod \frac{q}{2}
$$

We have an equation with $\lceil \frac{n}{2} \rceil + n - 1$ unknowns, but we can get this equation from any ciphertext, so given enought ciphertext we can solve this as a system of linear equations.

Let $L$ be a matrix with rows of the form $(a_1 - a_0, \dots a_{\lceil \frac{n}{2} \rceil} - a_0, -w_0, \dots -w_{n-1})$. Those are all known values we compute from different pairs of ciphertexts and keys. Similarly we compute a vector $S$ with elements of the form $\frac{s - a_0c(1)^2}{2}$. Let then our vector of unknowns be $Y = (x_1, \dots, x_{\lceil \frac{n}{2} \rceil}, m_0, \dots, m_{n-1})^T$. Then we can write our system of equations as

$$
L \times Y = S \mod \frac{q}{2}
$$

If we have enough equations, the matrix $L$ will be full rank, and the system will have an unique solution we can solve using gaussian elimination. We take the $(m_0, \dots, m_{n-1})$ part of $Y$ and decode that to get the flag:  `hitcon{ohno!y0u_broadc4st_t0o_much}`

### Implementation
```py
from Crypto.Util.number import long_to_bytes as l2b

def invertmodprime(f, p):
    T = Zx.change_ring(Integers(p)).quotient(MOD)
    return Zx(lift(1 / T(f)))

def convolution(f, g):
    return (f * g) % MOD

def balancedmod(f, q):
    g = list(((f[i] + q//2) % q) - q//2 for i in range(n))
    return Zx(g) % MOD

def invertmodpowerof2(f, q):
    assert q.is_power_of(2)
    g = invertmodprime(f, 2)
    while True:
        r = balancedmod(convolution(g, f), q)
        if r == 1:
            return g
        g = balancedmod(convolution(g, 2 - r), q)

def pseudoinverse(h):
    h_ = invertmodpowerof2(h % MOD, q)
    return ((u*MOD + v*(x-1)*h_) % (x ^ n-1))

def poly_to_vec(p):
    l = list(p)
    while len(l) < n:
        l.append(0)

    return vector(Zmod(q), l)

def poly_to_mat(p):
    l = list(p)
    while len(l) < n:
        l.append(0)

    mat = []
    for i in range(n):
        mat.append(l[(n-i):] + l[:(n-i)])

    return matrix(Zmod(q), mat).T

def decode(coeffs):
    text = 0
    for i, v in enumerate(coeffs):
        text += ((v+1) % 3) * 3**i
    return text

Zx.<x> = ZZ[]
cts = []
keys = []

f = open("output.txt").readlines()

for line in f:
    l = line.replace("^", "**")
    if line.startswith("data:"):
        cts.append(eval(l[5:]))
    elif line.startswith("key:"):
        keys.append(eval(l[4:]))

n, q = 263, 128
MOD = sum(x ^ i for i in range(n))
u = (MOD).change_ring(Zmod(128)).inverse_mod(x-1)
v = (x-1).change_ring(Zmod(128)).inverse_mod(MOD)
d = 36
c1 = cts[0](1) % q

L = []
S = []

for k, c in zip(keys, cts):
    h = k.change_ring(Integers(q))
    c = poly_to_vec(c)
    H = poly_to_mat(h)
    h_ = pseudoinverse(h)
    Ĥ = poly_to_mat(h_)
    a = (Ĥ.T * Ĥ).column(0)
    c = c.list()
    c = c + [0] * (n-len(c))
    b = Ĥ * vector(c)
    s = d - b*b
    w = list(-b * Ĥ)
    row = [a[i] - a[0] for i in range(1, n//2 + 1)] + w
    
    L.append(row)
    S.append(int(s - a[0]*c1^2)//2)


L = matrix(Zmod(q//2), L)
S = vector(Zmod(q//2), S)
sol = L.solve_right(S)
m = [{0: 0, 1: 1, 63: -1}[h] for h in sol[-n:]]
print(l2b(decode(m)))
```