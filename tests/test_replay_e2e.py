"""the whole media path, offline: real hevc nals are packetized per rfc
7798 (as the camera does), depacketized by this fork, muxed as hevc and
decoded. proves bug 2 stays fixed without a camera."""
import io
from fractions import Fraction
from pathlib import Path

import av

from nooie_proxy import codec
from nooie_proxy.h265 import H265PayloadDescriptor

MTU = 1180
FIXTURE = Path("tests/fixtures/baby_room_2k.h265")


def nals(data: bytes) -> list[bytes]:
    return [n for n in data.split(b"\x00\x00\x01") if len(n) >= 2]


def packetize(nal: bytes) -> list[bytes]:
    """rfc 7798: single-nal when it fits, fu fragments when it does not."""
    if len(nal) <= MTU:
        return [nal]
    kind = (nal[0] >> 1) & 0x3F
    indicator = bytes([(nal[0] & 0x81) | (49 << 1), nal[1]])
    body = nal[2:]
    chunks = [body[i : i + MTU] for i in range(0, len(body), MTU)]
    payloads = []
    for index, chunk in enumerate(chunks):
        fu = kind | (0x80 if index == 0 else 0) | (
            0x40 if index == len(chunks) - 1 else 0
        )
        payloads.append(indicator + bytes([fu]) + chunk)
    return payloads


def test_packetize_depacketize_roundtrip_is_lossless():
    source = nals(FIXTURE.read_bytes())
    for nal in source[:200]:
        rebuilt = b"".join(
            H265PayloadDescriptor.parse(p)[1] for p in packetize(nal)
        )
        assert rebuilt == b"\x00\x00\x01" + nal


def test_depacketized_stream_muxes_as_hevc_and_decodes_2k(tmp_path):
    codec.set_video_codec("h265")
    try:
        out = tmp_path / "replay.ts"
        container = av.open(str(out), "w", format="mpegts")
        stream = container.add_mux_stream("hevc", time_base=Fraction(1, 90000))
        pts = 0
        for nal in nals(FIXTURE.read_bytes()):
            data = b"".join(
                H265PayloadDescriptor.parse(p)[1] for p in packetize(nal)
            )
            packet = av.Packet(data)
            packet.pts = packet.dts = pts
            packet.stream = stream
            container.mux(packet)
            pts += 90000 // 30
        container.close()
        decoded = av.open(str(out))
        video = next(s for s in decoded.streams if s.type == "video")
        frames = [f for _, f in zip(range(20), decoded.decode(video))]
        assert frames, "nothing decoded"
        assert (frames[0].width, frames[0].height) == (2304, 1296)
    finally:
        codec.set_video_codec("h264")
