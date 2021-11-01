from random import randint, seed
from time import time
from math import sqrt, ceil, log2


attempt = 0  # for randomization
LOREM = """Lorem ipsum dolor sit amet, consectetur adipiscing elit, 
sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. 
Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris 
nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in 
reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla 
pariatur. Excepteur sint occaecat cupidatat non proident, sunt in 
culpa qui officia deserunt mollit anim id est laborum."""


def fast_mod_pwr(a, k, n):
    rem = 1
    rema = a % n
    while k:
        if k % 2:
            rem = rem * rema % n
            k -= 1
        else:
            rema = rema ** 2 % n
            k //= 2
    return rem


def encrypt(a, public_key):
    return fast_mod_pwr(from_bytes(a), *public_key)


def decrypt(c, private_key):
    return to_bytes(fast_mod_pwr(c, *private_key))


def gcd(a, b):
    rem = a % b
    if rem:
        return gcd(b, rem)
    return b


def xgcd(a, b):
    if b:
        x, y, g = xgcd(b, a % b)
        return y, x - a // b * y, g
    return 1, 0, a


def calculate_e(phi):
    global attempt
    while True:
        seed(time() + attempt)
        e = randint(2, phi - 1)
        if gcd(phi, e) == 1:
            return e
        attempt += 1


def calculate_d(e, phi):
    d = xgcd(e, phi)[0]
    return d + phi * (d < 0)


def generate_keys(keysize=1024):
    pwr = keysize // 2 + keysize % 2
    p = generate_prime(2 ** (pwr - 1), 2 ** pwr)
    q = generate_prime(2 ** (pwr - 1), 2 ** pwr)
    while p == q:
        q = generate_prime(2 ** (pwr - 1), 2 ** pwr)
    phi = (p - 1) * (q - 1)
    n = p * q
    e = calculate_e(phi)
    d = calculate_d(e, phi)
    return (e, n), (d, n)


def is_prime(p):
    if not p % 2:
        return False
    for i in range(3, round(sqrt(p)) + 1, 2):
        if not p % i:
            return False
    return True


def prime_test(p, tests=15):
    global attempt
    for test in range(tests):
        seed(time() + attempt)
        a = randint(2, p - 1)
        if fast_mod_pwr(a, p - 1, p) != 1:
            return False
        attempt += 1
    return True


def generate_prime(a, b):
    found = False
    global attempt
    while not found:
        seed(time() + attempt)
        p = randint(a, b)
        while not prime_test(p):
            p = randint(a, b)
        if a > 32 or is_prime(p):
            found = True
        attempt += 1
    return p


def to_bytes(data):
    if isinstance(data, int):
        return int(bin(data), 2).to_bytes(ceil(log2(data) + 6) // 8, byteorder="little")
    if isinstance(data, str):
        return data.encode('utf-8')


def from_bytes(byte):
    return int.from_bytes(byte, "little")


def split_bytes(data, max_length=1024):
    return [data[part * max_length: min((part + 1) * max_length, len(data))]
            for part in range(ceil(len(data) / max_length))]


def encrypt_data(data, public_key):
    return [to_bytes(encrypt(part, public_key)) for part in split_bytes(data, ceil(log2(public_key[1])) // 8)]


def decrypt_data(data, private_key):
    return b"".join([decrypt(from_bytes(part), private_key) for part in data])


if __name__ == '__main__':
    public, private = generate_keys(256)
    print(public, private)
    msg = to_bytes(LOREM)
    print(msg)
    encrypted = encrypt_data(msg, public)
    print(encrypted)
    print(decrypt_data(encrypt_data(msg, public), private))
