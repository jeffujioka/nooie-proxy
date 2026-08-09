"""compact pure-python twofish — the block cipher for the p2p control channel.

standard twofish (key-dependent s-boxes, pht, key add, ror/rol-by-1) over a
full-keying context (`{u32 s[256][4]; u32 K[40]}`). supports 128/192/256-bit
keys and round-trips the official ecb known-answer vectors (see __main__).
"""

def _gfm(a, b, p):  # gf(2^8) multiply mod primitive poly p (0x100 bit implicit)
    r = 0
    while b:
        if b & 1:
            r ^= a
        b >>= 1
        a <<= 1
        if a & 0x100:
            a ^= p
    return r & 0xff

_Q0 = ((8,1,7,13,6,15,3,2,0,11,5,9,14,12,10,4),
       (14,12,11,8,1,2,3,5,15,4,10,6,7,0,9,13),
       (11,10,5,14,6,13,9,0,12,8,15,3,2,4,7,1),
       (13,7,15,4,1,2,6,14,9,11,3,0,8,5,12,10))
_Q1 = ((2,8,11,13,15,7,6,14,3,1,9,4,0,10,12,5),
       (1,14,2,11,4,12,3,7,6,13,10,5,15,9,0,8),
       (4,12,7,5,1,6,9,10,0,14,13,8,2,11,3,15),
       (11,9,5,1,12,3,13,14,6,4,7,15,2,0,8,10))

def _qp(t, x):
    a, b = x >> 4, x & 0xf
    a, b = a ^ b, (a ^ ((b >> 1) | ((b << 3) & 0xf)) ^ ((8 * a) & 0xf)) & 0xf
    a, b = t[0][a], t[1][b]
    a, b = a ^ b, (a ^ ((b >> 1) | ((b << 3) & 0xf)) ^ ((8 * a) & 0xf)) & 0xf
    return (t[3][b] << 4) | t[2][a]

_q0 = [_qp(_Q0, i) for i in range(256)]
_q1 = [_qp(_Q1, i) for i in range(256)]

_MDS = ((0x01, 0xEF, 0x5B, 0x5B), (0x5B, 0xEF, 0xEF, 0x01),
        (0xEF, 0x5B, 0x01, 0xEF), (0xEF, 0x01, 0xEF, 0x5B))
_RS = ((0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E),
       (0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5),
       (0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19),
       (0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03))

def _rol(x, n): return ((x << n) | (x >> (32 - n))) & 0xffffffff
def _ror(x, n): return ((x >> n) | (x << (32 - n))) & 0xffffffff

_Q = (_q0, _q1)
# per-lane q-box sequence (inner->outer) for the key-dependent s-boxes; the
# k4/k3 stages are skipped for shorter keys (start = 4-k). validated exhaustively
# against the reference twofish for 128/192/256-bit keys.
_SEL = ((1, 1, 0, 0, 1), (0, 1, 1, 0, 0), (0, 0, 0, 1, 1), (1, 0, 1, 1, 0))

def _h(x, L, k):
    y = []
    for c in range(4):
        b = (x >> (8 * c)) & 0xff
        for s in range(4 - k, 5):
            b = _Q[_SEL[c][s]][b]
            if s < 4:
                b ^= (L[3 - s] >> (8 * c)) & 0xff
        y.append(b)
    z = 0
    for col in range(4):
        v = 0
        for row in range(4):
            v ^= _gfm(_MDS[col][row], y[row], 0x169)
        z |= v << (8 * col)
    return z

class Twofish:
    def __init__(self, key):
        n = len(key)
        k = n // 8
        w = [int.from_bytes(key[4 * i:4 * i + 4], "little") for i in range(2 * k)]
        Me = [w[2 * i] for i in range(k)]
        Mo = [w[2 * i + 1] for i in range(k)]
        S = []
        for i in range(k):
            blk = key[8 * i:8 * i + 8]
            sw = 0
            for col in range(4):
                v = 0
                for row in range(8):
                    v ^= _gfm(_RS[col][row], blk[row], 0x14D)
                sw |= v << (8 * col)
            S.insert(0, sw)
        self.S, self.k = S, k
        self.K = []
        for i in range(20):
            A = _h((2 * i) * 0x01010101, Me, k)
            B = _rol(_h((2 * i + 1) * 0x01010101, Mo, k), 8)
            self.K.append((A + B) & 0xffffffff)
            self.K.append(_rol((A + 2 * B) & 0xffffffff, 9))

    def _g(self, x): return _h(x, self.S, self.k)

    def encrypt(self, pt):
        R = [
            int.from_bytes(pt[4 * i : 4 * i + 4], "little") ^ self.K[i]
            for i in range(4)
        ]
        for r in range(16):
            t0 = self._g(R[0])
            t1 = self._g(_rol(R[1], 8))
            f0 = (t0 + t1 + self.K[2 * r + 8]) & 0xffffffff
            f1 = (t0 + 2 * t1 + self.K[2 * r + 9]) & 0xffffffff
            R[2] = _ror(R[2] ^ f0, 1)
            R[3] = _rol(R[3], 1) ^ f1
            R = [R[2], R[3], R[0], R[1]]
        R = [R[2], R[3], R[0], R[1]]
        return b"".join(
            ((R[i] ^ self.K[i + 4]) & 0xffffffff).to_bytes(4, "little")
            for i in range(4)
        )

    def decrypt(self, ct):
        R = [
            int.from_bytes(ct[4 * i : 4 * i + 4], "little") ^ self.K[i + 4]
            for i in range(4)
        ]
        for r in range(15, -1, -1):
            t0 = self._g(R[0])
            t1 = self._g(_rol(R[1], 8))
            f0 = (t0 + t1 + self.K[2 * r + 8]) & 0xffffffff
            f1 = (t0 + 2 * t1 + self.K[2 * r + 9]) & 0xffffffff
            R[2] = _rol(R[2], 1) ^ f0
            R[3] = _ror(R[3] ^ f1, 1)
            R = [R[2], R[3], R[0], R[1]]
        R = [R[2], R[3], R[0], R[1]]
        return b"".join(
            ((R[i] ^ self.K[i]) & 0xffffffff).to_bytes(4, "little")
            for i in range(4)
        )


if __name__ == "__main__":
    import binascii
    # official ecb_tbl.txt I=1 known-answer vectors (key, pt, ct)
    kats = [
        (
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "9F589F5CF6122C32B6BFEC2F2AE8C35A",
        ),
        (
            "0123456789ABCDEFFEDCBA98765432100011223344556677",
            "00000000000000000000000000000000",
            "CFD1D2E5A9BE9CDF501F13B892BD2248",
        ),
        (
            "0123456789ABCDEFFEDCBA987654321000112233445566778899AABBCCDDEEFF",
            "00000000000000000000000000000000",
            "37527BE0052334B89F0CFCCAE87CFA20",
        ),
    ]
    for kh, ph, ch in kats:
        t = Twofish(binascii.unhexlify(kh))
        ct = t.encrypt(binascii.unhexlify(ph))
        ciphertext = binascii.hexlify(ct).decode().upper()
        ok = ciphertext == ch
        rt = t.decrypt(ct) == binascii.unhexlify(ph)
        status = "ok" if ok else f"FAIL {ciphertext}"
        print(f"k{len(kh) * 4}: enc {status} dec {'ok' if rt else 'FAIL'}")
