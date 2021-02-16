import sha3, copy

# (mostly) From https://eth.wiki/en/concepts/ethash/ethash

# Assumes little endian bit ordering (same as Intel architectures)
def decode_int(s):
    return int(s[::-1].encode('hex'), 16) if s else 0

def encode_int(s):
    a = "%x" % s
    return '' if s == 0 else ('0' * (len(a) % 2) + a).decode('hex')[::-1]

def zpad(s, length):
    return s + '\x00' * max(0, length - len(s))

def serialize_hash(h):
    return ''.join([zpad(encode_int(x), 4) for x in h])

def deserialize_hash(h):
    return [decode_int(h[i:i+WORD_BYTES]) for i in range(0, len(h), WORD_BYTES)]

def hash_words(h, sz, x):
    if isinstance(x, list):
        x = serialize_hash(x)
    y = h(x)
    return deserialize_hash(y)

def serialize_cache(ds):
    return ''.join([serialize_hash(h) for h in ds])

serialize_dataset = serialize_cache

# sha3 hash function, outputs 64 bytes
def sha3_512(x):
    return hash_words(lambda v: sha3.sha3_512(v).digest(), 64, x)

def sha3_256(x):
    return hash_words(lambda v: sha3.sha3_256(v).digest(), 32, x)

def xor(a, b):
    return a ^ b

def isprime(x):
    for i in range(2, int(x**0.5)):
         if x % i == 0:
             return False
    return True

def clz(a):
    a = bin(a)[2:].zfill(32)
    count_zeros = 0
    for c in a:
        if c == '0':
            count_zeros += 1
        else:
            return count_zeros
    return count_zeros

def popcount(a):
    pass

Masks = [(1 << i) - 1 for i in range(65)]

def rol(value, left, bits):
    top = value >> (bits - left)
    bot = (value & Masks[bits - left]) << left
    return bot | top

FNV_PRIME = 0x1000193
FNV_OFFSET_BASIS = 0x811c9dc5

def fnv1a(a, b):
    return (a ^ b) * FNV_PRIME