import binascii, gmpy2
e=3
cipher = "]WӮ�j���[���"
cipher_in_bytes = str.encode(cipher)
cipher_in_bytes = b'Ji\x06!\xbd\x15\x0c\xf6\x93\xed\x8c\x85p\x8bm\x0f\xa2\xcc\x85\x0bHsdC\x08#\x8f8\x03\x1a\x931\x02\xf6f\xb8\x92h\x99`nI\x1f6\n$\xd2k\x9e\x91^\xd6\xa1(I+\x14G\x99\xe9\xee\xd2P\x05\n-\xef\xa2\xacSR\xb0I,\x98\x83(\xb0t6\xb8&\xa5\x00\xf9\x195\xacX\x1c\x0c`f\xa7\xa9IF\xf2\x1e)\x0b\x1b/\xbd\xf6s\xad\xb0\\\x04E\x90[\xdd\x88\x01\xc9<\xfbL\xe7C\xcdb\xbfy\xe9\x7f\x95\x9c\xb9D\x9f\xc3}\xbf\\\xd3\x15V[\xb0\xc43i\xe6G;\xc9}-\xb5\xcc,\x01\xdeu\x0b\x99Y\xb8\xde=S\x95\xf1\x1f\xa8\xbb\xe8\x8b\x8d\xfeR\x1dx-\xfdAfL\x08*\x80k\xfe\x7f0\x0bV3\'O\xdd_"\x93\xe0\xd0\xc2\x1e\xc6\xb1\xd2\xc9?\xc0M"\xf1\xaa\x1c\x9e\n\xad\xfa(T\xcf2YQ\xfc\xfe\x84\xecN\xd2\xa5\xc9\x10\xed\xb3+\xba\x9f%\xab\xfeSB\x03\xef>\xbb\x1d6\xfa;\x12U\xb8\xa3I\xc4\xa7pf\xd1\xc3\xf2e\x90\r\x11\xca\x1bj\x80f\xff\x01\xe4\x98\x05\x8dUz\x15\x05H\x82\xdd\x13l\x06N\x9c\xe2\x8e-D\x055vs\xac#\xf61\x06C\xdb\x0b\x93\xa3\x99n\xe6]\x15\xe0\x86\xeahw\x18\x01k\x18A\x08\xa7/\xc9y\xfar\xb4\x91:\xa7y(\x96\xf5\x1ch\xfc\x97\x91w5\xd7\xe2\x86K\xd3\x84\xcf\x9bw\xaf\xd2\xc6\xbd\xfc\xdd2T\x13\x9ai\xb6E\xb1RBK\xa9\x02y\xe2uV:\xf5/\xecH~h\xd0\xba<B-\x00\x07\xe2o\xfc\x9a\x03\xce\x98\x90\xdd8\x15:6F\xd4\x9d\xc0q\xe1\xfdz<B\x1a\xd2\x1bb\xebc\xce@\x88}\xd6\x0b`\x13J\x1e\xf0l`\x9e\xf4m\xb6\xd9\x92\x9e\xab\xfb\x15\x93-]z\xc7\x0b\xec\xf1\xb4\xca\xf8U\x14\xd3\x15\x1f0\xceie\xf9\xd1g!\xe8e\xb7\xd3\x01H\xf6\xb8F\xe5\x03\x15\xb7\x0e\x1e\xfdz\xd8\xe4\xff\x9f\x1d\x84\xfb\xa4\x10\x81\x16q\xe5m\xe2F\x96U\xce\xd0\x14\xd0\t\xe1\'\x978!\xf3#\n'
n = 720598231657797504789329857401395813824870018766460129406996744103908652477699772635990607038510802609167537764203555150021009794467954923810099523917220514714909319583601845015254858270299801261719571926369942640317975492862775832842358494746982769311653590169052104623893597295806222298685977264157244977070554711689467795083253766625992040570498399197574617603000857623815310804125701730810233728128488605244118787058999542602480643955518705855179070883426777487313505821271657536149061135309755522837705753195821528929295680640858852934959250042480246809310047903437548624254009311026327164086428305177099012645963023400493809033935058576889155735008973809505091804546218862087355691068996160031565680337069362289686614192251156959440231661050940075108641394940777665898597283268452342616559037590790443009855345379068106804618607516039905072613031066848988602991217489186761018199215937834452390019297396020648917474727829820438874219717224343401391663048330008619060439263946666442858611438157676164963529041502586177397063233751275569370599750394046286592712228141396860313739306784519505594863156278236095319192454238078172250931490290809666508894591672686420995702293267016203412119527290895508813173977511036388068802715837
def hastads():
        # Hastad attack for low public exponents
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


def string_to_number(s):
    """
    String to number.
    """
    if not len(s):
        return 0
    return int(binascii.hexlify(s), 16)


def number_to_string(n):
    """
    Number to string.
    """
    s = hex(n)[2:].rstrip("L")
    if len(s) % 2 != 0:
        s = "0" + s
    return binascii.unhexlify(s)

if __name__ == "__main__":
    print(type(cipher_in_bytes))
    hastads()