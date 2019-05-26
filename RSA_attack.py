import binascii
import gmpy2
import os
import sys
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



# Functions

def modular_inverse(a,n):
    a = a % n; 
    for x in range(1, n) : 
        if ((a * x) % n == 1) : 
            return x 
    return 1

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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Nishanth')
    args = parser.parse_args()
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    
    # Convert hex to long
    if args.p is not None:
        if args.p.startswith("0x"):
            args.p = int(args.p, 16)
        else:
            args.p = int(args.p)

    if args.q is not None:
        if args.q.startswith("0x"):
            args.q = int(args.q, 16)
        else:
            args.q = int(args.q)

    if args.p and args.q is not None:
       args.n = args.p * args.q
    elif args.n is not None:
        if args.n.startswith("0x"):
            args.n = int(args.n, 16)
        else:
            args.n = int(args.n)

    if args.e is not None:
        if args.e.startswith("0x"):
            args.e = int(args.e, 16)
        else:
            args.e = int(args.e)

