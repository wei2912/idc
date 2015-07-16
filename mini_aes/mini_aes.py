# constants

ROUNDS = 2

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

RCONS = [0x01, 0x02]

# procedures

def nibble_sub(ns):
    result = [SBOX[i] for i in ns]
    print("NibbleSub: {}".format(result))
    return result

def inv_nibble_sub(ns):
    result = [INV_SBOX[i] for i in ns]
    print("InvNibbleSub: {}".format(result))
    return result

def shift_row(ns):
    tmp = ns[1]
    ns[1] = ns[3]
    ns[3] = tmp
    print("ShiftRow: {}".format(ns))
    return ns

def mix_column(ns):
    n0 = ns[0]
    n1 = ns[1]
    n2 = ns[2]
    n3 = ns[3]
    result = [
        MULTI_3[n0] ^ MULTI_2[n1],
        MULTI_2[n0] ^ MULTI_3[n1],
        MULTI_3[n2] ^ MULTI_2[n3],
        MULTI_2[n2] ^ MULTI_3[n3]
    ]
    print("MixColumn: {}".format(result))
    return result

def key_addition(ws, ns):
    result = [w ^ n for (w, n) in zip(ws, ns)]
    print("Key Addition: {}".format(result))
    return result

# key schedule

def key_schedule(ks):
    ws = [[]] * (ROUNDS + 1)
    ws[0] = ks
    for i in range(0, ROUNDS):
        w = [0] * 4
        w[0] = ws[i][0] ^ SBOX[ws[i][3]] ^ RCONS[i]
        w[1] = ws[i][1] ^ w[0]
        w[2] = ws[i][2] ^ w[1]
        w[3] = ws[i][3] ^ w[2]
        ws[i + 1] = w
    print("Key Schedule: {}".format(ws))
    return ws

# encryption & decryption

def encrypt_block(ks, ns):
    print("Key: {}".format(ks))
    print("Plaintext Block: {}".format(ns))
    ws = key_schedule(ks)
    print("# Round 0")
    ns = key_addition(ws[0], ns)
    for i in range(0, ROUNDS):
        print("# Round {}".format(i + 1))
        ns = shift_row(nibble_sub(ns))
        if i != ROUNDS - 1:
            ns = mix_column(ns)
        ns = key_addition(ws[i + 1], ns)
    return ns

def decrypt_block(ks, ns):
    print("Key: {}".format(ks))
    print("Ciphertext Block: {}".format(ns))
    ws = key_schedule(ks)
    for i in range(ROUNDS - 1, -1, -1):
        print("# Round {}".format(i + 1))
        ns = key_addition(ws[i + 1], ns)
        if i != ROUNDS - 1:
            ns = mix_column(ns)
        ns = inv_nibble_sub(shift_row(ns))
    print("# Round 0")
    ns = key_addition(ws[0], ns)
    return ns

encrypt_block([12, 3, 15, 0], [9, 12, 6, 3])
print("---")
decrypt_block([12, 3, 15, 0], [7, 2, 12, 6])

