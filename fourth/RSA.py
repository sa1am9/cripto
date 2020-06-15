def rsa_initialize(bit_length):  # Will NOT be auto tested, manual checked

    from itertools import islice
    import random

    def primes():
        if hasattr(primes, "D"):
            D = primes.D
        else:
            primes.D = D = {}

        def sieve():
            q = 2
            while True:
                if q not in D:
                    yield q
                    D[q * q] = [q]
                else:
                    for p in D[q]:
                        D.setdefault(p + q, []).append(p)
                    del D[q]

                q += 1

        return sieve()

    primes_array = list(islice(primes(), 0, 2**bit_length))
    e = random.choice(primes_array)
    n = random.choice(primes_array)
    d = random.choice(primes_array)

    return e, n, d


def rsa_encrypt(msg, n, e):  # Will be auto tested

    cipher = [(ord(char) ** e)% n for char in msg]

    return cipher




def rsa_decrypt(msg, n, d):  # Will be auto tested

    plain = [chr((char ** d) % n) for char in msg]

    return ''.join(plain)