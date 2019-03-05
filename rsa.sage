
DEBUG = 0

class Rsa:
    def generate_key(self, bits):
        self.log("Generation of {bits}-bits keys".format(bits=bits))

        self.log("    Generation of prime 'p'")
        p = random_prime((2 ** bits)- 1, True, 2 ** (bits - 1))
        self.log("    Done\n")

        self.log("    Generation of prime 'q'")
        q = random_prime((2 ** bits)-1, True, 2 ** (bits - 1))
        self.log("    Done\n")

        self.log("    Calculation 'n' and 'phi_n'")
        self.n = p * q
        phi_n = (p-1)*(q-1)
        self.log("    Done\n")

        self.log("    Calculation 'e'")
        while True:
            # self.e = random_prime((2 ** bits)-1, False, 2 ** (bits - 1))
            self.e = ZZ.random_element(0, phi_n)
            if gcd(phi_n, self.e) == 1:
                break
        self.log("    Done\n")

        self.log("    Calculation 'd'")
        self.d = inverse_mod(self.e, phi_n)
        self.log("    Done\n")

        print "Public Key:"
        print "    e = {e}".format(e=self.e)
        print "    n = {n}\n".format(n=self.n)
        print "Private Key:"
        print "    d = {d}".format(d=self.d)
        print "    n = {n}\n".format(n=self.n)

    def encode(self, message):
        self.log("Encoding: start")
        encoded = []
        R = IntegerModRing(self.n)
        for char in message:
            encoded.append(R(ord(char)) ** self.e)

        print "Plain text: {plain}".format(plain=message)
        print "Cipher text: {cipher}\n".format(cipher=encoded)
        self.log("Encoding: done")
        return encoded

    def decode(self, cipher):
        self.log("Decoding: start")
        decoded = []
        R = IntegerModRing(self.n)
        for char in cipher:
            decoded.append(chr(R(char) ** self.d))

        print "Cipher text: {cipher}".format(cipher=cipher)
        print "Plain text: {plain}\n".format(plain=decoded)
        self.log("Decoding: done")
        return decoded

    def log(self, s):
        if DEBUG:
            print s


rsa = Rsa()
rsa.generate_key(512)
encoded = rsa.encode("Hello")
rsa.decode(encoded)
