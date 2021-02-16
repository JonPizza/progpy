from util import *

from kiss99 import Kiss99
from keccak import keccak_f800_progpow

PROGPOW_PERIOD = 10
PROGPOW_LANES = 16
PROGPOW_REGS = 32
PROGPOW_DAG_LOADS = 4
PROGPOW_CACHE_BYTES = 16 * 1024
PROGPOW_CNT_DAG = 64
PROGPOW_CNT_CACHE = 11
PROGPOW_CNT_MATH = 18

ETHASH_DATASET_PARENTS = 256

def get_mix_list(seed, lane_id):
    fnv_hash = FNV_OFFSET_BASIS
    kiss = Kiss99(
        fnv1a(fnv_hash, seed),
        fnv1a(fnv_hash, seed >> 32),
        fnv1a(fnv_hash, lane_id),
        fnv1a(fnv_hash, lane_id),
    )

    mix = []
    for i in range(PROGPOW_REGS):
        mix.append(kiss.next_int())

    return mix

def swap(l1, i1, l2, i2):
    tmp = l1[i1]
    l1[i1] = l2[i2]
    l2[i1] = tmp

def merge(a, b, r):
    if r == 0:
        return (a * 33) + b
    elif r == 1:
        return (a ^ b) * 33
    elif r == 2:
        return (a << ((r >> 16) % 31) + 1) ^ b
    elif r == 3:
        return (a >> ((r >> 16) % 31) + 1) ^ b

def math(a, b, r):
    f = {
        0: lambda a, b: a + b,
        1: lambda a, b: a * b,
        2: lambda a, b: a * b >> 32,
        3: lambda a, b: min([a, b]),
        4: lambda a, b: a,
        5: lambda a, b: a + b,
        6: lambda a, b: a & b,
        7: lambda a, b: a | b,
        8: lambda a, b: a ^ b,
        9: lambda a, b: clz(a) + clz(b),
        10: lambda a, b: a + b,
    }

def progpow_init(prog_seed):
    z = fnv1a(FNV_OFFSET_BASIS, prog_seed)
    w = fnv1a(z, prog_seed >> 32)
    jsr = fnv1a(w, prog_seed)
    jcong = fnv1a(jsr, prog_seed >> 32)

    prog_rnd = Kiss99(
        z, w, jsr, jcong
    )

    mix_seq_dst = list(range(PROGPOW_REGS))
    mix_seq_src = list(range(PROGPOW_REGS))

    for i in list(range(PROGPOW_REGS))[::-1]:
        j = prog_rnd.next_int() % (i + 1)
        swap(mix_seq_dst, i, mix_seq_src, j)
        j = prog_rnd.next_int() % (i + 1)
        swap(mix_seq_dst, i, mix_seq_src, j)
    
    return prog_rnd, mix_seq_dst, mix_seq_src

def progpow_loop(prog_seed, loop, mix, dag):
    dag_entry = [[]] * PROGPOW_LANES
    dag_base_idx = mix[loop % PROGPOW_LANES][0] % (DAG_BYTES / (PROGPOW_LANES * PROGPOW_DAG_LOADS))

    for lane_id in range(PROGPOW_LANES):
        dag_lane = dag_base_idx * PROGPOW_LANES + (lane_id ^ loop) % PROGPOW_LANES
        for _ in range(PROGPOW_DAG_LOADS):
            dag_entry[lane_id].append(dag[dag_lane * PROGPOW_DAG_LOADS + i])
    
    prog_rnd, mix_seq_dst, mix_seq_src = progpow_init(prog_seed)
    src_i, dst_i = 0, 0

    r = max([PROGPOW_CNT_CACHE, PROGPOW_CNT_MATH])
    for i in range(r):
        if i < PROGPOW_CNT_CACHE:
            src = mix_seq_src[src_i % PROGPOW_REGS] 
            dst = mix_seq_src[dst_i % PROGPOW_REGS] 
            sel = prog_rnd.next_int()

            for lane_id in range(PROGPOW_LANES):
                offset = mix[lane_id][src] % PROGPOW_CACHE_BYTES
                mix[lane_id][dst] = merge(mix[lane_id][dst], dag[offset], sel)

            src_i += 1
            dst_i += 1


def progpow_hash(prog_seed, nonce, header, dag):
    mix = []

    state = [
        header[:4],
        header[4:] + [nonce % 2 ** 32, nonce >> 32],
        [0x00000001, 0, 0, 0, 0],
        [0, 0, 0, 0x80008081, 0],
        [0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0],
    ]

    hash_init = keccak_f800_progpow(state)

    seed = (hash_init[1] << 32) | hash_init[0]

    for lane_id in range(PROGPOW_LANES):
        mix.append(get_mix_list(seed, lane_id))
    
    for i in range(PROGPOW_CNT_DAG):
        progpow_loop(prog_seed, i, mix, dag)
    
    digest_lane = [FNV_OFFSET_BASIS] * PROGPOW_LANES
    for lane_id in range(PROGPOW_LANES):
        for i in range(PROGPOW_REGS):
            digest_lane[lane_id] = fnv1a(digest_lane[lane_id], mix[lane_id][i])
    
    digest = [FNV_OFFSET_BASIS] * 8

    for lane_id in range(PROGPOW_LANES):
        digest[lane_id % 8] = fnv1a(digest[lane_id % 8], digest_lane[lane_id])
    
    state = [
        hash_init[:4],
        hash_init[4:] + digest[:2],
        [digest[2:6]],
        [digest[7], 0x00000001, 0, 0, 0],
        [0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0x80008081],
    ]

    hash_final = keccak_f800_progpow(state)

    return hash_final

