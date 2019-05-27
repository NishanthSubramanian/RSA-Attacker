import binascii
import gmpy2
import os
import sys, math
import sympy
from sympy.solvers import solve
from sympy import Symbol
import argparse
from Crypto.PublicKey import RSA
import requests
import re
from cryptography.fernet import Fernet
from gmpy2 import isqrt
import signal

public_key_filename = input("Enter name of public key file : ")
key_data = open(public_key_filename, 'rb').read()
key = RSA.importKey(key_data)
print("[*] n: " + str(key.n))
print("[*] e: " + str(key.e))
n = key.n
e = key.e
if key.has_private():
    print("[*] d: " + str(key.d))
    print("[*] p: " + str(key.p))
    print("[*] q: " + str(key.q))



# cipher = "]WӮ�j���[���"
cipher_in_bytes = b'Ji\x06!\xbd\x15\x0c\xf6\x93\xed\x8c\x85p\x8bm\x0f\xa2\xcc\x85\x0bHsdC\x08#\x8f8\x03\x1a\x931\x02\xf6f\xb8\x92h\x99`nI\x1f6\n$\xd2k\x9e\x91^\xd6\xa1(I+\x14G\x99\xe9\xee\xd2P\x05\n-\xef\xa2\xacSR\xb0I,\x98\x83(\xb0t6\xb8&\xa5\x00\xf9\x195\xacX\x1c\x0c`f\xa7\xa9IF\xf2\x1e)\x0b\x1b/\xbd\xf6s\xad\xb0\\\x04E\x90[\xdd\x88\x01\xc9<\xfbL\xe7C\xcdb\xbfy\xe9\x7f\x95\x9c\xb9D\x9f\xc3}\xbf\\\xd3\x15V[\xb0\xc43i\xe6G;\xc9}-\xb5\xcc,\x01\xdeu\x0b\x99Y\xb8\xde=S\x95\xf1\x1f\xa8\xbb\xe8\x8b\x8d\xfeR\x1dx-\xfdAfL\x08*\x80k\xfe\x7f0\x0bV3\'O\xdd_"\x93\xe0\xd0\xc2\x1e\xc6\xb1\xd2\xc9?\xc0M"\xf1\xaa\x1c\x9e\n\xad\xfa(T\xcf2YQ\xfc\xfe\x84\xecN\xd2\xa5\xc9\x10\xed\xb3+\xba\x9f%\xab\xfeSB\x03\xef>\xbb\x1d6\xfa;\x12U\xb8\xa3I\xc4\xa7pf\xd1\xc3\xf2e\x90\r\x11\xca\x1bj\x80f\xff\x01\xe4\x98\x05\x8dUz\x15\x05H\x82\xdd\x13l\x06N\x9c\xe2\x8e-D\x055vs\xac#\xf61\x06C\xdb\x0b\x93\xa3\x99n\xe6]\x15\xe0\x86\xeahw\x18\x01k\x18A\x08\xa7/\xc9y\xfar\xb4\x91:\xa7y(\x96\xf5\x1ch\xfc\x97\x91w5\xd7\xe2\x86K\xd3\x84\xcf\x9bw\xaf\xd2\xc6\xbd\xfc\xdd2T\x13\x9ai\xb6E\xb1RBK\xa9\x02y\xe2uV:\xf5/\xecH~h\xd0\xba<B-\x00\x07\xe2o\xfc\x9a\x03\xce\x98\x90\xdd8\x15:6F\xd4\x9d\xc0q\xe1\xfdz<B\x1a\xd2\x1bb\xebc\xce@\x88}\xd6\x0b`\x13J\x1e\xf0l`\x9e\xf4m\xb6\xd9\x92\x9e\xab\xfb\x15\x93-]z\xc7\x0b\xec\xf1\xb4\xca\xf8U\x14\xd3\x15\x1f0\xceie\xf9\xd1g!\xe8e\xb7\xd3\x01H\xf6\xb8F\xe5\x03\x15\xb7\x0e\x1e\xfdz\xd8\xe4\xff\x9f\x1d\x84\xfb\xa4\x10\x81\x16q\xe5m\xe2F\x96U\xce\xd0\x14\xd0\t\xe1\'\x978!\xf3#\n'
# # n = 720598231657797504789329857401395813824870018766460129406996744103908652477699772635990607038510802609167537764203555150021009794467954923810099523917220514714909319583601845015254858270299801261719571926369942640317975492862775832842358494746982769311653590169052104623893597295806222298685977264157244977070554711689467795083253766625992040570498399197574617603000857623815310804125701730810233728128488605244118787058999542602480643955518705855179070883426777487313505821271657536149061135309755522837705753195821528929295680640858852934959250042480246809310047903437548624254009311026327164086428305177099012645963023400493809033935058576889155735008973809505091804546218862087355691068996160031565680337069362289686614192251156959440231661050940075108641394940777665898597283268452342616559037590790443009855345379068106804618607516039905072613031066848988602991217489186761018199215937834452390019297396020648917474727829820438874219717224343401391663048330008619060439263946666442858611438157676164963529041502586177397063233751275569370599750394046286592712228141396860313739306784519505594863156278236095319192454238078172250931490290809666508894591672686420995702293267016203412119527290895508813173977511036388068802715837


class PrivateKey(object):
    def __init__(self, p, q, e, n):
        t = (p-1)*(q-1)
        d = modular_inverse(e, t)
        self.key = RSA.construct((n, e, d, p, q))

    def decrypt(self, cipher):
        try:
            tmp_priv_key = tempfile.NamedTemporaryFile()
            with open(tmp_priv_key.name, "wb") as tmpfd:
                tmpfd.write(str(self).encode('utf8'))
            tmp_priv_key_name = tmp_priv_key.name

            tmp_cipher = tempfile.NamedTemporaryFile()
            with open(tmp_cipher.name, "wb") as tmpfd:
                tmpfd.write(cipher)
            tmp_cipher_name = tmp_cipher.name

            with open('/dev/null') as DN:
                openssl_result = subprocess.check_output(['openssl',
                                                          'rsautl',
                                                          '-raw',
                                                          '-decrypt',
                                                          '-in',
                                                          tmp_cipher_name,
                                                          '-inkey',
                                                          tmp_priv_key_name],
                                                         stderr=DN)
                return openssl_result
        except:
            return self.key.decrypt(cipher)

    def __str__(self):
        # Print armored private key
        return self.key.exportKey().decode("utf-8")


class WienerAttack(object):
    def rational_to_continous_frac(self, x, y):
        a = x // y
        if a * y == x:
            return [a]
        else:
            quotients = self.rational_to_continous_frac(y, x - a * y)
            quotients.insert(0, a)
            return quotients

    def convergents_from_continous_frac(self, frac):
        convs = []
        for i in range(len(frac)):
            convs.append(self.continous_frac_to_rational(frac[0:i]))
        return convs

    def continous_frac_to_rational(self, frac):
        if len(frac) == 0:
            return (0, 1)
        elif len(frac) == 1:
            return (frac[0], 1)
        else:
            remainder = frac[1:len(frac)]
            (num, denom) = self.continous_frac_to_rational(remainder)
            return (frac[0] * num + denom, num)

    def is_perfect_square(self, n):
        h = n & 0xF
        if h > 9:
            return -1

        if (h != 2 and h != 3 and h != 5 and h != 6 and h != 7 and h != 8):
            t = self.isqrt(n)
            if t*t == n:
                return t
            else:
                return -1

        return -1

    def isqrt(self, n):
        if n == 0:
            return 0
        a, b = divmod(n.bit_length(), 2)
        x = 2**(a+b)
        while True:
            y = (x + n//x)//2
            if y >= x:
                return x
            x = y

    def __init__(self, n, e):
        self.d = None
        self.p = None
        self.q = None
        sys.setrecursionlimit(100000)
        frac = self.rational_to_continous_frac(e, n)
        convergents = self.convergents_from_continous_frac(frac)
        for (k, d) in convergents:
            if k != 0 and (e * d - 1) % k == 0:
                phi = (e * d - 1) // k
                s = n - phi + 1
                discr = s*s - 4*n
                if(discr >= 0):
                    t = self.is_perfect_square(discr)
                    if t != -1 and (s + t) % 2 == 0:
                        self.d = d
                        x = Symbol('x')
                        roots = solve(x**2 - s * x + n, x)
                        if len(roots) == 2:
                            self.p = roots[0]
                            self.q = roots[1]
                        break

# Attacks

# Wiener's attack
def wiener():
    wiener = WienerAttack(n, e)
    if wiener.p is not None and wiener.q is not None:
        p = wiener.p
        q = wiener.q
        priv_key = PrivateKey(int(p), int(q),
                              int(e), int(n))
        print(priv_key)
    priv_key = None
    return priv_key

# Hastad attack for low public exponents
def hastads():
    if e <= 11 and cipher_in_bytes is not None:
        orig = string_to_number(cipher_in_bytes)
        c = orig
        while True:
            # e th root of c
            m = gmpy2.iroot(c, e)[0]
            if pow(m, e, n) == orig:
                result = number_to_string(m)
                print(result)
                break
            c += n
    return

class FactorizationError(Exception):
    pass

# Fermat factorization for close primes
def fermat(fermat_timeout = 10):
    try:
        with timeout(seconds=fermat_timeout):
            a = isqrt(n)
            temp = a*a - n
            b = isqrt(n)
            while b*b != temp:
                a = a+1
                temp = a*a - n
                b = isqrt(temp)
            p = a+b
            q = a-b
            assert n == p*q
    except FactorizationError:  
        return
    priv_key = None
    if q is not None:
        priv_key = PrivateKey(int(p), int(q),
                              int(e), int(n))
        print(priv_key)

    return priv_key

# Pollard p-1 factorization
def pollard():
    z = []
    prime = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59,
             61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131,
             137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197,
             199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271,
             277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353,
             359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433,
             439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509,
             521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601,
             607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677,
             683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769,
             773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859,
             863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953,
             967, 971, 977, 983, 991, 997]

    def gcd(a, b):
        if b == 0:
            return a
        return gcd(b, a % b)

    def e(a, b):
        return pow(a, b, n)

    def mysqrt(n):
        x = n
        y = []
        while(x > 0):
            y.append(x % 100)
            x = x // 100
        y.reverse()
        a = 0
        x = 0
        for p in y:
            for b in range(9, -1, -1):
                if(((20*a+b)*b) <= (x*100+p)):
                    x = x*100+p - ((20*a+b)*b)
                    a = a*10+b
                    break
        return a

    B1 = mysqrt(n)
    for j in range(0, len(prime)):
        for i in range(1, int(math.log(B1)/math.log(prime[j]))+1):
            z.append(prime[j])
    p = None
    q = None
    flag = 0
    for pp in prime:
        i = 0
        x = pp
        while(1):
            x = e(x, z[i])
            i = i+1
            y = gcd(n, x-1)
            if(y != 1):
                p = y
                q = n//y
                flag = 1
                break
            if(i >= len(z)):
                flag = 2
                break
        if flag == 1 or flag ==2:
            break

    priv_key = None
    if q is not None:
        priv_key = PrivateKey(int(p), int(q),
                              int(e), int(n))
        print(priv_key)

    return priv_key
        
def tiny_q():
    priv_key = None
    for prime in sympy.primerange(2,100000):
        if n % prime == 0:
            q = prime
            p = n // q
            priv_key = PrivateKey(int(p), int(q),
                              int(e), int(n))
            print(priv_key)
    return priv_key


# Functions

def string_to_number(s):
    if not len(s):
        return 0
    return int(binascii.hexlify(s), 16)


def number_to_string(n):
    s = hex(n)[2:].rstrip("L")
    if len(s) % 2 != 0:
        s = "0" + s
    return binascii.unhexlify(s)


def modular_inverse(a, n):
    if n < 2:
        raise ValueError("Mod less than 2")

    x, y, g = xgcd(a, n)

    if g != 1:
        raise ValueError("no modular inverse exists")
    else:
        return x % n


def xgcd(a, b):
    """
    Extended Euclid GCD algorithm.
    Return (x, y, g) : a * x + b * y = gcd(a, b) = g.
    """
    if a == 0:
        return 0, 1, b
    if b == 0:
        return 1, 0, a

    px, ppx = 0, 1
    py, ppy = 1, 0

    while b:
        q = a // b
        a, b = b, a % b
        x = ppx - q * px
        y = ppy - q * py
        ppx, px = px, x
        ppy, py = py, y

    return ppx, ppy, a


# Copyright source http://stackoverflow.com/a/22348885
class timeout:
    def __init__(self, seconds=10, error_message='[-] Timeout'):
        self.seconds = seconds
        self.error_message = error_message

    def handle_timeout(self, signum, frame):
        raise FactorizationError(self.error_message)

    def __enter__(self):
        signal.signal(signal.SIGALRM, self.handle_timeout)
        signal.alarm(self.seconds)

    def __exit__(self, type, value, traceback):
        signal.alarm(0)


if __name__ == "__main__":
    # hastads()
    # key = wiener()
    # key = fermat()
    # key = pollard()
    key = tiny_q()
    if key is not None:
        cipherfile = input("Enter value of cipher file : ")
        with open(cipherfile, 'rb') as infile:
            cipher = infile.read()
        decrypted = key.decrypt(cipher)
        print("Decrypted text : %r" % (decrypted))
