import binascii
import gmpy2
import os
import sys
from sympy.solvers import solve
from sympy import Symbol
import argparse
from Crypto.PublicKey import RSA


class getPublicKey(object):
    def __init__(self, key):
        try:
            pub = RSA.importKey(key)
        except ValueError as e:
            print(e)
            sys.exit(1)
        self.n = pub.n
        # print("n")
        # print(self.n)
        self.e = pub.e
        self.key = key

class getPrivateKey(object):
    def __init__(self, n, e):
        phi = n-1
        d = modular_inverse(e, phi)
        p = n
        q = special_unity(1)
        self.key = RSA.RSAImplementation(use_fast_math=False).construct((n,e,d,p,q))

class WienerClass(object):
    def __init__(self, n, e):
        self.d = None
        self.p = None
        self.q = None
        sys.setrecursionlimit(100000)
        frac = rational_to_contfrac(e, n)
        convergents = convergents_from_contfrac(frac)
        for (k, d) in convergents:
            if k != 0 and (e * d - 1) % k == 0:
                phi = (e * d - 1) // k
                s = n - phi + 1
                discr = s*s - 4*n
                if(discr >= 0):
                    t = is_perfect_square(discr)
                    if t != -1 and (s + t) % 2 == 0:
                        self.d = d
                        x = Symbol('x')
                        roots = solve(x**2 - s * x + n, x)
                        if len(roots) == 2:
                            self.p = roots[0]
                            self.q = roots[1]
                        break


class RSAAttack(object):
    def __init__(self, args):
        key = open(args.publickey, 'rb').read()
        self.pubkeyfile = args.publickey
        self.pub_key = getPublicKey(key)
        self.priv_key = None
        self.args = args
        self.unciphered = None

        # Read n and e from publickey file
        if not args.n or not args.e:
            pkey = getPublicKey(key)
            if not args.n:
                args.n = pkey.n
            if not args.e:
                args.e = pkey.e

        if args.uncipher is not None:
            self.cipher = args.uncipher
        else:
            self.cipher = None
        print(type(self.cipher))
        return

    def check_if_n_prime(self):
        # Check if n is a prime
        if gmpy2.is_prime(self.pub_key.n):
            self.priv_key = getPrivateKey(self.pub_key.n, self.pub_key.e)

    def hastads(self):
        # Hastad attack for low public exponents
        if self.pub_key.e <= 11 and self.cipher is not None:
            orig = string_to_number(self.cipher)
            c = orig
            while True:
                m = gmpy2.iroot(c, self.pub_key.e)[0]
                if pow(m, self.pub_key.e, self.pub_key.n) == orig:
                    self.unciphered = number_to_string(m)
                    break
                c += self.pub_key.n
        return

    def wieners(self):
        wiener = WienerClass(self.pub_key.n, self.pub_key.e)
        if wiener.p is not None and wiener.q is not None:
            p = wiener.p
            q = wiener.q
            priv_key = PrivateKey(int(p), int(q),
                                        int(e), int(n))
            print(priv_key)
    return

# Functions

def modular_inverse(a,n):
    if n < 2:
        raise ValueError("modulus must be greater than 1")

    x, y, g = xgcd(a, n)

    if g != 1:
        raise ValueError("no invmod for given @a and @n")
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

class special_unity(int):
    def __sub__(a, b):
        assert a == 1
        assert b == 1
        return 1

def string_to_number(s):
    if not len(s):
        return 0
    return int(binascii.hexlify(s), 16)


def number_to_string(n):
    s = hex(n)[2:].rstrip("L")
    if len(s) % 2 != 0:
        s = "0" + s
    return binascii.unhexlify(s)


def rational_to_contfrac(x, y):
        a = x // y
        if a * y == x:
            return [a]
        else:
            pquotients = rational_to_contfrac(y, x - a * y)
            pquotients.insert(0, a)
            return pquotients

def convergents_from_contfrac(frac):
    convs = []
    for i in range(len(frac)):
        convs.append(contfrac_to_rational(frac[0:i]))
    return convs

def contfrac_to_rational(frac):
    if len(frac) == 0:
        return (0, 1)
    elif len(frac) == 1:
        return (frac[0], 1)
    else:
        remainder = frac[1:len(frac)]
        (num, denom) = contfrac_to_rational(remainder)
        return (frac[0] * num + denom, num)

def is_perfect_square(n):
    h = n & 0xF
    if h > 9:
        return -1

    if (h != 2 and h != 3 and h != 5 and h != 6 and h != 7 and h != 8):
        t = isqrt(n)
        if t*t == n:
            return t
        else:
            return -1

    return -1

def isqrt(n):
    if n == 0:
        return 0
    a, b = divmod(n.bit_length(), 2)
    x = 2**(a+b)
    while True:
        y = (x + n//x)//2
        if y >= x:
            return x
        x = y


if __name__ == "__main__":
    temp = RSAAttack()