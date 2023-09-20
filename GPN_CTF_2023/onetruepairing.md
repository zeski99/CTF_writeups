# one true pairing
- Category: Crypto
- Points: 1000
> The new chip I bought might have been too cheap. After installing it, my computer sometimes behaved weirdly. Upon researching, I found some weird communication with a single remote host. They all start with "RDY" and continue with seemingly random data. Because I was not successful at extracting more information from the suspicious chip, I tried exploring the remote host. \
I could extract the python script that is running on the remote. One dependency is missing. I replaced it with a script that behaves similar. Please find out, what information you can get from the remote. \
> `ncat --ssl one-true-pairing-0.chals.kitctf.de 1337`

## Challenge source
### main.py
```py
import sys
import random
from secret import get_next_seed, store_leaked_data, store_exec_status, get_flag, get_scheduled_cmds


RESEED_AFTER = 1000000


def xor_bytes(a, b):
    return bytes(map(lambda x: x[0] ^ x[1], zip(a,b)))


class Handler:
    def __init__(self) -> None:
        self.handling = True
        self.reseed()

    def randbytes(self, n):
        self.rng_used += n
        b = self.rng.randbytes(n)
        return b

    def reseed(self):
        seed_bytes = get_next_seed()
        if len(seed_bytes) != 12:
            self.send_raw(b'ERROR: No more pre-shared seeds')
            exit()
        self.rng = random.Random()
        self.rng.seed(seed_bytes)
        self.rng_used = 0

    def recv_msg(self, length, default=None):
        received = b''
        while len(received) < length:
            new_input = sys.stdin.buffer.read(length - len(received))
            received += new_input.strip().replace(b' ', b'')

        if len(received) == 0 and default:
            return default
        try:
            return received
        except:
            return b''

    def send_raw(self, msg):
        sys.stdout.buffer.write(msg)
        sys.stdout.buffer.flush()

    def start_encrypted(self):
        return

    def end_encrypted(self):
        if self.rng_used > RESEED_AFTER:
            self.reseed()

    def recv_encrypted(self):
        msg = b''
        try:
            len_otp = self.randbytes(1)
            len_encrypted = self.recv_msg(1, default=len_otp)
            length = int.from_bytes(xor_bytes(len_otp, len_encrypted), 'little')

            if length == 0:
                self.end_encrypted()
                return msg

            otp = self.randbytes(length)
            received = self.recv_msg(length)
            msg = xor_bytes(otp, received)
        except:
            self.handling = False
        finally:
            self.end_encrypted()
        return msg

    def send_encrypted(self, msg):
        try:
            assert len(msg) < 256
            otp = self.randbytes(1) + self.randbytes(len(msg)) # split for receiver
            self.send_raw(xor_bytes(otp, len(msg).to_bytes(1, 'little') + msg))
        except:
            self.handling = False
            self.send_raw(b'ERR: %d' % (len(msg)))
        finally:
            self.end_encrypted()

    def process_commands(self, cmd_msg: bytes):
        response = b''

        while len(cmd_msg) > 0:
            cursor = 4
            current_cmd = cmd_msg[:cursor]
            if current_cmd == b'LEAK':
                length = cmd_msg[cursor]
                cursor += 1
                store_leaked_data(cmd_msg[cursor:cursor+length])
                cursor += length
            elif current_cmd == b'EXEC':
                store_exec_status(cmd_msg[cursor])
                cursor += 1
            elif current_cmd == b'FLAG':
                response += get_flag()
            elif current_cmd == b'EXIT':
                self.handling = False
            else:
                response += b'ERROR'
            cmd_msg = cmd_msg[cursor:]
        response = response[:255] # truncate response to max length

        response += get_scheduled_cmds(255 - len(response))
        return response

    def handle(self):
        self.send_raw(b'RDY')
        while self.handling:
            try:
                cmd_msg = self.recv_encrypted()
                if not self.handling: return

                response = self.process_commands(cmd_msg)
                self.send_encrypted(response)
                if not self.handling: return
            except:
                return


def main():
    srv = Handler()
    srv.handle()

if __name__ == '__main__':
    main()
```
### secret.py
```py
import random
import os

FLAG_RESPONSE = b'Please keep this for me: ' + os.getenv('FLAG', 'GPNCTF{fake_flag}').encode()

def get_next_seed():
    return os.urandom(12)

def store_leaked_data(data):
    # store leaked data from remote for later processing
    
    return

def store_exec_status(status):
    # store or process exec result status
    
    return

def get_flag():
    return FLAG_RESPONSE

MAX_COMMANDS = 3
def get_scheduled_cmds(max_len):
    cmds = b''
    for _ in range(MAX_COMMANDS):
        if max_len > 0 and random.random() > 0.7:
            if max_len >= 16 and random.random() > 0.9:
                cmds += b'\x05\x0enc -lvnp 31337'
            cmds += bytes([random.randint(1, 4)])
        else:
            break
    return cmds
```

## Solution steps
We see we are dealing with some kind of encrypted command service, which samples a random stream and xors it with your input, tries to execute the few commands it has, and returns you encrypted output. The only command we really care about is `"FLAG"`, as if we can execute anything else, we can also just get flag, so why bother. The interesting thing we notice is in case the command isn't valid, the server will add `"ERROR"` to the output.

First thing we need to figure out is how to even send commands. The first byte you send gets xored with a random byte, and that is the length of your input. Since we don't know the random value yet, we just send one byte at a time and check if the server returned anything to figure out that length. After that, we recieve the output. This is where the useful stuff starts happening. Since what we send to the server is just random garbage once decrypted, the response should be just a bunch of `"ERROR"` strings concatinated. This allows us to learn the random stream. And since it's using pythons random, this is just outputs from a Mersenne twister. Next step: recover the state.

To recover the state I was very lazy dealing with the random outputs, ignoring anything I found annoying to deal with. Since the server sometimes at random appends some stuff to the output, I just decided to ignore those cases and move on. So for the state recovery I only used responses with just `"ERROR"` in them. All that's left is find a MT predictor that works even with fixed state (or ask your teammates if someone has one already), and we can recover the state of the server, then use this to send the `"FLAG"` command and decrypt the flag the server sends us.

### mtz3.py
```py
from tqdm import tqdm
from z3 import *

class MT19937:
    W = 32
    N = 624
    M = 397
    R = 31
    A = 0x9908B0DF
    U = 11
    D = 0xFFFFFFFF
    S = 7
    B = 0x9D2C5680
    T = 15
    C = 0xEFC60000
    L = 18

    F = 1812433253

    def __init__(self, seed=None):
        if seed is None:
            seed = int.from_bytes(os.urandom(self.W // 8), byteorder='little')
        self.state = [seed % (2**self.W)]
        for i in range(1, self.N):
            self.state.append((self.F * (self.state[-1] ^ (self.state[-1] >> (self.W - 2))) + i) % (2**self.W))
        self.idx = self.N

    def rand(self):
        if self.idx >= self.N:
            self._twist()
        y = self.state[self.idx]
        y ^= (y >> self.U) & self.D
        y ^= (y << self.S) & self.B
        y ^= (y << self.T) & self.C
        y ^= y >> self.L
        self.idx += 1
        return y % (2**self.W)

    def getrandbits(self, n):
        iters = (n + 31) // 32
        result = self.rand()
        if n <= 32:
            return result >> (32 - n)
        for i in range(iters - 2):
            result |= self.rand() << ((i + 1) * 32)
        if n % 32:
            result |= (self.rand() >> (32 - (n % 32))) << ((iters - 1) * 32)
        else:
            result |= self.rand() << ((iters - 1) * 32)
        return result

    def _twist(self):
        lower_mask = (1 << self.R) - 1
        upper_mask = (~lower_mask) % (2**self.W)
        for i in range(0, self.N):
            x = (self.state[i] & upper_mask) + (self.state[(i + 1) % self.N] & lower_mask)
            xA = x >> 1
            if x % 2 != 0:
                xA ^= self.A
            self.state[i] = self.state[(i + self.M) % self.N] ^ xA
        self.idx = 0

class Z3MT19937:
    W = 32
    N = 624
    M = 397
    R = 31
    A = 0x9908B0DF
    U = 11
    D = 0xFFFFFFFF
    S = 7
    B = 0x9D2C5680
    T = 15
    C = 0xEFC60000
    L = 18

    F = 1812433253

    def __init__(self):
        self.state = [BitVec(f"state_{i}", 32) for i in range(self.N)]
        self.idx = self.N

    def rand(self):
        if self.idx >= self.N:
            self._twist()
        y = self.state[self.idx]
        y ^= LShR(y, self.U) & self.D
        y ^= (y << self.S) & self.B
        y ^= (y << self.T) & self.C
        y ^= LShR(y, self.L)
        self.idx += 1
        return simplify(y)

    def getrandbits(self, n):
        if n <= 32:
            return LShR(self.rand(), 32 - n)
        else:
            iters = (n + 31) // 32
            result = ZeroExt(n - 32, self.rand())
            for i in range(iters - 2):
                result |= ZeroExt(n - 32, self.rand()) << ((i + 1) * 32)
            if n % 32:
                result |= ZeroExt(n - 32, LShR(self.rand(), 32 - (n % 32))) << ((iters - 1) * 32)
            else:
                result |= ZeroExt(n - 32, self.rand()) << ((iters - 1) * 32)
        assert result.size() == n, (result.size(), n)
        return simplify(result)


    def _twist(self):
        lower_mask = (1 << self.R) - 1
        upper_mask = (~lower_mask) % (2**self.W)
        for i in range(0, self.N):
            x = (self.state[i] & upper_mask) + (self.state[(i + 1) % self.N] & lower_mask)
            xA = LShR(x, 1)
            xA = If(x & 1 == 1, xA ^ self.A, xA)
            self.state[i] = simplify(self.state[(i + self.M) % self.N] ^ xA)
        self.idx = 0

def crack(inputs):
    fr = Z3MT19937()
    initstate = fr.state[:]

    s = Solver()
    
    for l1, l2, l3, inp in tqdm(inputs):
        fr.getrandbits(8)
        fr.getrandbits(l1 * 8)
        fr.getrandbits(8)
        known = fr.getrandbits(l3 * 8)
        if l2 == l3 and l2 >= 4:
            s.add(inp == known)
    assert s.check() == sat

    dup = MT19937()
    dup.state = [s.model()[x].as_long() for x in initstate]
    for l1, l2, l3, inp in tqdm(inputs):
        dup.getrandbits(8)
        dup.getrandbits(l1 * 8)
        dup.getrandbits(8)
        dup.getrandbits(l3 * 8)
        
    return dup
```

### sol.py
```python
from pwn import *
from itertools import count
from mtz3 import crack

LOCAL = False

if LOCAL:
    io = process(['python3', 'main.py'])
    timeout = 0.02
else:
    timeout = 0.05
    io = remote("one-true-pairing-0.chals.kitctf.de", 1337, ssl=True)

io.recvuntil(b'RDY')

def get_some_state():
    io.send(b"\0")

    for i in count(1):
        io.send(b"\0")
        if io.recv(1, timeout):
            break
    n = min((i+3)//4 * 5, 255)
    ret = io.recv(n)
    while (r := io.recv(1, timeout)):
        ret += r

    print(len(ret), len(ret) - n)
    return i, n, len(ret), int.from_bytes(xor(ret, b"ERROR")[:n], "little")

states = [get_some_state() for _ in range(50)]

rng = crack(states)

otp = rng.getrandbits(8) + rng.getrandbits(8*4).to_bytes(4, "little")

payload = b"\x04FLAG"

io.send(xor(payload, otp))

l = io.recv(1)[0] ^ rng.getrandbits(8)

ct = io.recv(l)

print(xor(ct, rng.getrandbits(8*l).to_bytes(l, "little")))
```
### flag
> `GPNCTF{1ns4n3_07P.1_mean,y0u_r3c0v3r3d_th3_wh0l3_st4t3!_:(_1bd69ef4858a2f51lol637b39a8b4a3bf6d109a8}`