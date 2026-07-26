"""apeman p2p registration layer.

before the camera will accept a webrtc call, the caller publishes its nat
mapping on nooie's regional p2p ("apeman") servers: server discovery (getsrv)
-> natcheck (NatOne / NatGetInfo) -> PutNatInfo. this module speaks that rpc —
cipher, wire framing, message bodies, and a `register(uid)` orchestrator.
"""

from __future__ import annotations

import hashlib
import random
import socket
import struct
from dataclasses import dataclass

from .twofish import Twofish

# --- crypto -----------------------------------------------------------------

# each apeman rpc "sail" body is enciphered with twofish-256 in ecb mode over
# 16-byte blocks with pkcs#7 padding. the 32-byte key is per-message (see
# sail_key). the pure twofish impl is validated against the reference vectors.

APEMAN_SALT = "ApEMaNSNoOiE"


def sail_key(method: str, trans_id: int) -> bytes:
    """derive the 32-byte twofish key for one apeman rpc message.

    the key is the ascii md5 hexdigest of ``"%s%u%s" % (method, trans_id,
    APEMAN_SALT)``, where `method` is the rpc method string and `trans_id` the
    transaction id (both echoed request<->response). 32 ascii hex bytes feed the
    twofish key schedule as a 256-bit key.
    """
    inner = f"{method}{trans_id}{APEMAN_SALT}".encode()
    return hashlib.md5(inner).hexdigest().encode()  # 32 ascii bytes


def _pkcs7(data: bytes) -> bytes:
    n = 16 - (len(data) % 16)
    return data + bytes([n]) * n


def _unpkcs7(data: bytes) -> bytes:
    n = data[-1]
    if not 1 <= n <= 16 or data[-n:] != bytes([n]) * n:
        raise ValueError("bad padding")
    return data[:-n]


def block_encrypt(data: bytes, key: bytes) -> bytes:
    """twofish-256-ecb (pkcs#7) — enciphers one sail rpc body."""
    tf = Twofish(key)
    padded = _pkcs7(data)
    return b"".join(tf.encrypt(padded[i:i + 16]) for i in range(0, len(padded), 16))


def block_decrypt(blob: bytes, key: bytes) -> bytes:
    """inverse of block_encrypt: twofish-256-ecb then strip pkcs#7."""
    tf = Twofish(key)
    out = b"".join(tf.decrypt(blob[i:i + 16]) for i in range(0, len(blob), 16))
    return _unpkcs7(out)


# --- rpc framing (protobuf ReqHeader + twofish body) ------------------------

# every apeman rpc rides a 4-byte big-endian total-length prefix (which counts
# itself: prefix = 4 + len(header)) followed by a cleartext protobuf ReqHeader
# whose field 11 carries the twofish-256-ecb'd body. header fields: field1=23,
# field3=version "5.0.0", field4=method, field5=transId, field8=1,
# field9=rpc_type(=1), field11=enc(body), field14=0; the optional code/code_msg
# (6,7) are response-only.

RPC_VERSION = b"5.0.0"


def _uv(n: int) -> bytes:
    """protobuf base-128 varint."""
    out = b""
    while True:
        b, n = n & 0x7F, n >> 7
        out += bytes([b | 0x80 if n else b])
        if not n:
            return out


def _v(tag: int, val: int) -> bytes:
    return _uv(tag << 3) + _uv(val)


def _s(tag: int, val: bytes) -> bytes:
    return _uv((tag << 3) | 2) + _uv(len(val)) + val


def build_rpc(method: str, trans_id: int, body: bytes, rpc_type: int = 1) -> bytes:
    """frame one request: 4-byte BE total length + ReqHeader nanopb (twofish body
    in field 11). the length prefix counts itself (4 + len(header))."""
    enc = block_encrypt(body, sail_key(method, trans_id))
    hdr = (_v(1, 23) + _s(3, RPC_VERSION) + _s(4, method.encode())
           + _v(5, trans_id) + _v(8, 1) + _v(9, rpc_type) + _s(11, enc)
           + _v(14, 0))
    return struct.pack(">I", 4 + len(hdr)) + hdr


def parse(buf: bytes) -> dict:
    """decode a flat protobuf into {tag: int | bytes} (last wins per tag). in a
    response ReqHeader: field4=method, field5=transId, field6=code, field11=body
    (still enciphered; decrypt with sail_key(method, transId))."""
    i, out = 0, {}
    while i < len(buf):
        key = buf[i]; i += 1
        tag, wt = key >> 3, key & 7
        if wt == 0:
            v = s = 0
            while True:
                b = buf[i]; i += 1
                v |= (b & 0x7F) << s; s += 7
                if not b & 0x80:
                    break
            out[tag] = v
        elif wt == 2:
            n = buf[i]; i += 1
            out[tag] = buf[i:i + n]; i += n
        else:
            break
    return out


# body layouts (all bodies use type selector field1 = 2). the identity carried
# is the account `uid` (the api-token's uid claim): getsrv puts it in field6, the
# nat messages in field3. PutNatInfo appends the reflexive/local endpoint as a
# field-6 submessage.


def getsrv_body(uid: str) -> bytes:
    """getsrv body: {1: 2, 4: 0x01, 6: uid}. returns the region's first nat
    server (host, port) in the response's field-2 submessage."""
    return _v(1, 2) + _s(4, b"\x01") + _s(6, uid.encode())


def nat_body(uid: str) -> bytes:
    """shared NatOne / NatGetInfo body: {1: 2, 3: uid, 4: ""}."""
    return _v(1, 2) + _s(3, uid.encode()) + _s(4, b"")


def putnatinfo_body(uid: str, nattype: int, lan_ip: str, lan_port: int,
                    wan_ip: str, wan_port: int) -> bytes:
    """PutNatInfo body: the nat envelope + a field-6 natinfo submessage
    {1: 0, 7: nattype, 8: lan_ip, 9: lan_port, 11: wan_ip, 13: wan_port}."""
    sub = (_v(1, 0) + _v(7, nattype) + _s(8, lan_ip.encode()) + _v(9, lan_port)
           + _s(11, wan_ip.encode()) + _v(13, wan_port))
    return _v(1, 2) + _s(3, uid.encode()) + _s(4, b"") + _s(6, sub)


def decode_response(frame: bytes) -> tuple[str, int, dict]:
    """strip the length prefix, parse the ReqHeader, decrypt+walk the body.
    returns (method, trans_id, body-dict)."""
    hdr = parse(frame[4:] if len(frame) > 4 else frame)
    method = hdr.get(4, b"")
    method = method.decode() if isinstance(method, bytes) else str(method)
    trans_id = hdr.get(5, 0)
    body = hdr.get(11, b"")
    clear = block_decrypt(body, sail_key(method, trans_id)) if body else b""
    return method, trans_id, parse(clear)


# --- endpoints --------------------------------------------------------------

# server discovery hits the policy host on tcp 9000 and returns the region's nat
# servers; natcheck then runs against those (udp :5083/:5084).
POLICY_HOST = "policy-eu.nooie.com"
POLICY_PORT = 9000


# --- natcheck registration orchestrator -------------------------------------

# publish the caller's nat mapping so the camera can reach it: getsrv -> NatOne
# -> NatGetInfo -> PutNatInfo, keying every body by (method, transId). the
# returned Registration keeps its udp socket open so the mapping stays live.


@dataclass
class Registration:
    uid: str
    nat_server: tuple[str, int]
    lan_ip: str
    lan_port: int
    wan_ip: str
    wan_port: int
    nattype: int
    _udp: socket.socket  # kept open so the nat mapping survives


def _tid() -> int:
    return random.randint(1, 0xFFFF)


def _tcp_rpc(host: str, port: int, method: str, body: bytes,
             timeout: float = 6.0) -> tuple[str, int, dict]:
    with socket.create_connection((host, port), timeout) as s:
        s.sendall(build_rpc(method, _tid(), body))
        buf = b""
        while len(buf) < 4 or len(buf) < struct.unpack(">I", buf[:4])[0]:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
    return decode_response(buf)


def register(uid: str, timeout: float = 6.0) -> Registration:
    """run getsrv + natcheck + PutNatInfo for `uid`; returns a live Registration.
    raises on any step that does not confirm (getsrv/NatOne must answer, and
    PutNatInfo must return field1 == 0 = success)."""
    # 1. getsrv (tcp 9000) -> first nat server.
    _, _, g = _tcp_rpc(POLICY_HOST, POLICY_PORT, "Getsrv", getsrv_body(uid), timeout)
    srv = parse(g[2]) if isinstance(g.get(2), bytes) else {}
    nat = (srv[4].decode(), srv[5])

    # 2. NatOne (udp) from a kept-open socket -> our reflexive endpoint + 2nd srv.
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(timeout)
    udp.sendto(build_rpc("NatOne", _tid(), nat_body(uid)), nat)
    wan_ip = wan_port1 = second = None
    for _ in range(6):  # drain NatOne + the server-pushed NatCheckData
        try:
            data, _from = udp.recvfrom(4096)
        except socket.timeout:
            break
        m, _t, b = decode_response(data)
        if m == "NatOne":
            wan_ip = b[1].decode(); wan_port1 = b[2]
            sub = parse(b[5]) if isinstance(b.get(5), bytes) else {}
            second = (sub[1].decode(), b.get(4, sub.get(3)))
        if wan_ip and m == "NatCheckData":
            break
    if not wan_ip:
        raise RuntimeError("apeman NatOne: no response from nat server")

    # 3. NatGetInfo (udp) to the second server -> a second mapped port (nat type).
    wan_port2 = wan_port1
    if second:
        udp.sendto(build_rpc("NatGetInfo", _tid(), nat_body(uid)), second)
        try:
            data, _from = udp.recvfrom(4096)
            _m, _t, b = decode_response(data)
            wan_port2 = b.get(2, wan_port1)
        except socket.timeout:
            pass
    nattype = 5 if wan_port2 != wan_port1 else 0  # 5 = SYMMETRIC_NAT

    # 4. PutNatInfo (tcp, first nat server) -> publishes the mapping, ret == 0.
    lan_ip = udp.getsockname()[0]
    if lan_ip in ("0.0.0.0", ""):
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect(nat); lan_ip = probe.getsockname()[0]; probe.close()
    lan_port = udp.getsockname()[1]
    body = putnatinfo_body(uid, nattype, lan_ip, lan_port, wan_ip, wan_port1)
    _, _, p = _tcp_rpc(nat[0], nat[1], "PutNatInfo", body, timeout)
    if p.get(1) != 0:
        raise RuntimeError(f"apeman PutNatInfo failed: {p}")
    return Registration(uid, nat, lan_ip, lan_port, wan_ip, wan_port1, nattype, udp)
