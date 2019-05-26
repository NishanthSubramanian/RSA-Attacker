
class RSAAttack(object):
    def __init__(self, args):
        if '*' in args.publickey or '?' in args.publickey:
            self.pubkeyfilelist = glob(args.publickey)
            self.args = args

        else:
            if not isinstance(args.publickey, str):
                args.publickey = args.publickey.name

            key = open(args.publickey, 'rb').read()
            self.pubkeyfile = args.publickey
            self.pub_key = PublicKey(key)
            self.priv_key = None
            self.args = args
            self.unciphered = None

            # Read n and e from publickey file
            if not args.n or not args.e:
                pkey = PublicKey(key)
                if not args.n:
                    args.n = pkey.n
                if not args.e:
                    args.e = pkey.e

            if args.uncipher is not None:
                self.cipher = args.uncipher
            else:
                self.cipher = None
        return

    def hastads(self):
            # Hastad attack for low public exponents
            if self.pub_key.e <= 11 and self.cipher is not None:
                orig = s2n(self.cipher)
                c = orig
                while True:
                    m = gmpy2.iroot(c, self.pub_key.e)[0]
                    if pow(m, self.pub_key.e, self.pub_key.n) == orig:
                        self.unciphered = n2s(m)
                        break
                    c += self.pub_key.n
            return