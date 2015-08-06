# constants

ROUNDS = 5

SBOX = [
    0x0E, 0x04, 0x0D, 0x01, 0x02, 0x0F, 0x0B, 0x08,
    0x03, 0x0A, 0x06, 0x0C, 0x05, 0x09, 0x00, 0x07
]

INV_SBOX = [
    0x0E, 0x03, 0x04, 0x08, 0x01, 0x0C, 0x0A, 0x0F,
    0x07, 0x0D, 0x09, 0x06, 0x0B, 0x02, 0x00, 0x05
]

MULTI_2 = [
    0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E,
    0x03, 0x01, 0x07, 0x05, 0x0B, 0x09, 0x0F, 0x0D
]

MULTI_3 = [
    0x00, 0x03, 0x06, 0x05, 0x0C, 0x0F, 0x0A, 0x09,
    0x0B, 0x08, 0x0D, 0x0E, 0x07, 0x04, 0x01, 0x02
]

RCONS = [0x01, 0x02, 0x04, 0x08, 0x03]

# procedures

def nibble_sub(ns):
    return [SBOX[n] for n in ns]

def inv_nibble_sub(ns):
    return [INV_SBOX[n] for n in ns]

def shift_row(ns):
    assert len(ns) == 4
    tmp = ns[1]
    ns[1] = ns[3]
    ns[3] = tmp
    return ns 

def mix_column(ns):
    assert len(ns) == 4
    n0 = ns[0]
    n1 = ns[1]
    n2 = ns[2]
    n3 = ns[3]
    return [
        MULTI_3[n0] ^ MULTI_2[n1],
        MULTI_2[n0] ^ MULTI_3[n1],
        MULTI_3[n2] ^ MULTI_2[n3],
        MULTI_2[n2] ^ MULTI_3[n3]
    ]

def key_addition(ws, ns):
    assert len(ws) == len(ns) == 4
    return [w ^ n for (w, n) in zip(ws, ns)]

# key schedule

def key_schedule(k):
    assert len(k) == 4
    ws = [[]] * (ROUNDS + 1)
    ws[0] = k
    for i in range(0, ROUNDS):
        w = [0] * 4
        w[0] = ws[i][0] ^ SBOX[ws[i][3]] ^ RCONS[i]
        w[1] = ws[i][1] ^ w[0]
        w[2] = ws[i][2] ^ w[1]
        w[3] = ws[i][3] ^ w[2]
        ws[i + 1] = w
    return ws

# encryption & decryption

def round(ws, ns, i):
    if i == 0:
        ns = key_addition(ws[0], ns)
    ns = shift_row(nibble_sub(ns))
    if i != ROUNDS - 1:
        ns = mix_column(ns)
    ns = key_addition(ws[i + 1], ns)
    return ns

def inv_round(ws, ns, i):
    ns = key_addition(ws[i + 1], ns)
    if i != ROUNDS - 1:
        ns = mix_column(ns)
    ns = inv_nibble_sub(shift_row(ns))
    if i == 0:
        ns = key_addition(ws[0], ns)
    return ns

def encrypt_block(k, p):
    assert len(k) == len(p) == 4
    ws = key_schedule(k)
    assert len(ws) == ROUNDS + 1

    ns = p
    for i in range(0, ROUNDS):
        ns = round(ws, ns, i)
    return ns

def decrypt_block(k, c):
    assert len(k) == len(c) == 4
    ws = key_schedule(k)
    assert len(ws) == ROUNDS + 1

    ns = c
    for i in range(ROUNDS - 1, -1, -1):
        ns = inv_round(ws, ns, i)
    return ns

