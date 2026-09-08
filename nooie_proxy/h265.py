# nooie_proxy/h265.py
"""rfc 7798 h.265 payload handling, mirroring aiortc's h264 module.

the ipc100c streams h.265 while announcing it over an sdp this proxy labels
h264, so the depacketizer is selected by the session codec rather than by
the negotiated mime type (see rtc._enable_h265_depacketization).
"""

NAL_HEADER_SIZE = 2
NAL_TYPE_AP = 48
NAL_TYPE_FU = 49
# blas, idrs and cra (16..21) start a group of pictures; a consumer joining
# mid-stream also needs the parameter sets, so vps and sps count as well.
IRAP_TYPES = frozenset(range(16, 22))
OPENER_TYPES = IRAP_TYPES | {32, 33}


def nal_type(header_byte: int) -> int:
    return (header_byte >> 1) & 0x3F


class H265PayloadDescriptor:
    def __init__(self, first_fragment: bool) -> None:
        self.first_fragment = first_fragment

    def __repr__(self) -> str:
        return f"H265PayloadDescriptor(FF={self.first_fragment})"

    @classmethod
    def parse(cls, data: bytes) -> tuple["H265PayloadDescriptor", bytes]:
        if len(data) < NAL_HEADER_SIZE:
            raise ValueError("NAL unit is too short")
        kind = nal_type(data[0])

        if kind == NAL_TYPE_FU:
            if len(data) < NAL_HEADER_SIZE + 1:
                raise ValueError("FU is too short")
            fu_header = data[2]
            first = bool(fu_header & 0x80)
            output = b""
            if first:
                # rebuild the original two-byte nal header: keep the
                # forbidden bit and both layer-id halves, swap the type in.
                real_type = fu_header & 0x3F
                output += b"\x00\x00\x01"
                output += bytes([(data[0] & 0x81) | (real_type << 1), data[1]])
            output += data[NAL_HEADER_SIZE + 1 :]
            return cls(first_fragment=first), output

        if kind == NAL_TYPE_AP:
            output = b""
            pos = NAL_HEADER_SIZE
            while pos < len(data):
                if len(data) < pos + 2:
                    raise ValueError("AP length field is truncated")
                size = int.from_bytes(data[pos : pos + 2], "big")
                pos += 2
                if size == 0 or len(data) < pos + size:
                    raise ValueError("AP unit is truncated")
                output += b"\x00\x00\x01" + data[pos : pos + size]
                pos += size
            if not output:
                raise ValueError("AP carries no units")
            return cls(first_fragment=True), output

        if kind > 47:
            raise ValueError(f"NAL unit type {kind} is not supported")
        # single nal unit packet
        return cls(first_fragment=True), b"\x00\x00\x01" + data


def h265_depayload(payload: bytes) -> bytes:
    return H265PayloadDescriptor.parse(payload)[1]


def opens_a_group(access_unit: bytes) -> bool:
    """true when the unit carries an irap picture or the parameter sets."""
    return any(
        len(nal) >= NAL_HEADER_SIZE and nal_type(nal[0]) in OPENER_TYPES
        for nal in access_unit.split(b"\x00\x00\x01")
    )
