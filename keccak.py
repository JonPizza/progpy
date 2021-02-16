from operator import xor
from copy import deepcopy
from functools import reduce

from util import rol
from tests.keccak_test import keccak_test

# The Keccak-f round constants.
RoundConstants = [
    0x00000001, 0x00008082, 0x0000808A, 0x80008000, 0x0000808B, 0x80000001, 0x80008081, 0x00008009,
    0x0000008A, 0x00000088, 0x80008009, 0x8000000A, 0x8000808B, 0x0000008B, 0x00008089, 0x00008003,
    0x00008002, 0x00000080, 0x0000800A, 0x8000000A, 0x80008081, 0x00008080
]

RotationConstants = [
  [  0,  1, 62, 28, 27, ],
  [ 36, 44,  6, 55, 20, ],
  [  3, 10, 43, 25, 39, ],
  [ 41, 45, 15, 21,  8, ],
  [ 18,  2, 61, 56, 14, ]
]

def keccak_f800_round(A, RC):
    """
    from https://github.com/ctz/keccak/blob/master/keccak.py
    because jesus christ the pseudocode at https://keccak.team/keccak_specs_summary.html
    is confusing as heck1! (or maybe i am just bad at programming, no way to tell for sure)
    """
    W, H = 5, 5
    lanew = 32 # for Keccak f800 (800 / 25 = 32)
    
    # theta
    C = [reduce(xor, A[x]) for x in range(W)]
    D = [0] * W
    for x in range(W):
        D[x] = C[(x - 1) % W] ^ rol(C[(x + 1) % W], 1, lanew)
        for y in range(H):
            A[x][y] ^= D[x]
    
    # rho and pi
    B = [[0] * W for x in range(H)]
    for x in range(W):
        for y in range(H):
            B[y % W][(2 * x + 3 * y) % H] = rol(A[x][y], RotationConstants[y][x] % 32, lanew)
            
    # chi
    for x in range(W):
        for y in range(H):
            A[x][y] = B[x][y] ^ ((~ B[(x + 1) % W][y]) & B[(x + 2) % W][y])
    
    # iota
    A[0][0] ^= RC

    return A

def keccak_f800_progpow(state):
    for i in range(22):
        keccak_f800_round(state, RoundConstants[i])
    
    return state[:8]

if __name__ == '__main__':
    state = [
        [0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0],
    ]

    keccak_f800_progpow(state)

    print([[hex(i) for i in a] for a in state])