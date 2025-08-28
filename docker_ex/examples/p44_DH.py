import numpy as np
import primesieve
from random import randint

# sudo apt-get update
# sudo apt-get install libprimesieve-dev
# pip install primesieve

def generate_primes(n1,n2):
    return primesieve.primes(n1, n2)

def int_from_bytes(n):
    try:  # python 3
        return int.from_bytes(n, byteorder="big")
    except:
        import struct
        format = 'Q' * (len(n) / 8)
        return struct.unpack(format, n)[0]

class DiffieHellman(object):
    """
    Demo  implementation of the Diffie-Hellman protocol.
    """

    def __init__(self, generator=2, group=None, keyBytes=72):
        """
        Generate group and keys.
        """
        if group:
            self.group=group
        else:
            self.group = self.getPrime()
        self.generator = generator
        self.privateKey = self.genPrivateKey(keyBytes)
        self.publicKey = self.genPublicKey()

    def genPrivateKey(self, size):
        """
        Private Key = random with the specified number of bits (size*8)
        http://stefanocappellini.com/generate-pseudorandom-bytes-with-python/
        """
        return np.random.bytes(size)

    def genPublicKey(self):
        """
        key = generator ** privateKey % group.
        """
        return pow(self.generator, int_from_bytes(self.privateKey), self.group)

    def sharedSecret(self, otherKey):
        """
        sharedSecret = otherKey ** privateKey % group
        """
        return pow(otherKey, int_from_bytes(self.privateKey), self.group)

    def getPrime(self, min=1000):
        """
        Eratosthenes sieve http://code.activestate.com/recipes/117119/
        https://github.com/hickford/primesieve-python
        """
        prime_list = generate_primes(min, min+100)
        while (not prime_list):
          prime_list = generate_primes(min, min+100)
        n=randint(0, len(prime_list)-1)
        return prime_list[n]


if __name__=="__main__":
    first = DiffieHellman()
    # generator and group as public
    print("generator=%s, group=%s" % (first.generator, first.group))
    two = DiffieHellman(generator=first.generator, group=first.group)

    print('shared secret [1] = %s' % first.sharedSecret(two.publicKey))
    print('shared secret [2] = %s' % two.sharedSecret(first.publicKey))
