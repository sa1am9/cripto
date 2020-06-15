from hashlib import sha256


def generate_aes_key(key):
    h = sha256(key)
    res = h.digest()[:16]
    return res