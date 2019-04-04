from sage.crypto.util import ascii_to_bin, bin_to_ascii

DEBUG = 0

class RSA:
    def generate_key(self, bits):
        self.log("Generation of {bits}-bits keys".format(bits=bits))

        self.log("Generation of prime 'p'")
        p = random_prime((2 ** bits)- 1, False, 2 ** (bits - 1))
        self.log("Done\n")

        self.log("Generation of prime 'q'")
        q = random_prime((2 ** bits)-1, False, 2 ** (bits - 1))
        self.log("Done\n")

        self.log("Calculation 'n' and 'phi_n'")
        self.n = p * q
        phi_n = (p-1)*(q-1)
        self.log("Done\n")

        self.log("Calculation 'e'")
        while True:
            self.e = ZZ.random_element(2**bits, phi_n)
            if gcd(phi_n, self.e) == 1:
                break
        self.log("Done\n")

        self.log("Calculation 'd'")
        self.d = inverse_mod(self.e, phi_n)
        self.log("Done\n")

        print("Public Key:")
        print("    e = {e}".format(e=self.e))
        print("    n = {n}\n".format(n=self.n))
        print("Private Key:")
        print("    d = {d}".format(d=self.d))
        print("    n = {n}\n".format(n=self.n))

    def encode(self, message, block_size = 32):
        self.log("Encoding: start")
        R = IntegerModRing(self.n)
        raw = ascii_to_bin(message)
        encoded = []
        i = 0
        while i < len(raw) / block_size:
            encoded.append(
                R(int(str(raw[i*block_size: (i+1)*block_size]).rjust(block_size, '0'), 2)) ** self.e)
            i += 1

        print("Plain text: {plain}".format(plain=message))
        print("Cipher text: {cipher}\n".format(cipher=encoded))
        self.log("Encoding: done")
        return encoded

    def decode(self, cipher, block_size = 32):
        self.log("Decoding: start")
        R = IntegerModRing(self.n)
        decoded = ""
        for block in cipher:
            decoded += bin_to_ascii(bin(R(block) ** self.d)[2:].zfill(block_size))

        print("Cipher text: {cipher}".format(cipher=cipher))
        print("Plain text: {plain}\n".format(plain=decoded))
        self.log("Decoding: done")
        return decoded        

    def log(self, s):
        if DEBUG:
            print(s)


input1 = "Hello"
input2 = """
  Alice was beginning to get very tired of sitting by her sister
on the bank, and of having nothing to do:  once or twice she had
peeped into the book her sister was reading, but it had no
pictures or conversations in it, `and what is the use of a book,'
thought Alice `without pictures or conversation?'

  So she was considering in her own mind (as well as she could,
for the hot day made her feel very sleepy and stupid), whether
the pleasure of making a daisy-chain would be worth the trouble
of getting up and picking the daisies, when suddenly a White
Rabbit with pink eyes ran close by her.

  There was nothing so VERY remarkable in that; nor did Alice
think it so VERY much out of the way to hear the Rabbit say to
itself, `Oh dear!  Oh dear!  I shall be late!'  (when she thought
it over afterwards, it occurred to her that she ought to have
wondered at this, but at the time it all seemed quite natural);
but when the Rabbit actually TOOK A WATCH OUT OF ITS WAISTCOAT-
POCKET, and looked at it, and then hurried on, Alice started to
her feet, for it flashed across her mind that she had never
before seen a rabbit with either a waistcoat-pocket, or a watch to
take out of it, and burning with curiosity, she ran across the
field after it, and fortunately was just in time to see it pop
down a large rabbit-hole under the hedge.
"""
block_size = 128
key_bits = 2048

rsa = RSA()
rsa.generate_key(key_bits)
encoded = rsa.encode(input2, block_size)
decoded = rsa.decode(encoded, block_size)

print "good" if input2 == decoded else "bad"
