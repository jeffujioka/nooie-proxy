"""extract committed test fixtures from the spike artefacts (run on jeff).

usage: python tools/make_fixtures.py /tmp/nooie-h265.ts tests/fixtures/
"""
import sys
from pathlib import Path

import av

SECONDS = 2.5


def main() -> None:
    source, target = sys.argv[1], Path(sys.argv[2])
    target.mkdir(parents=True, exist_ok=True)
    container = av.open(source)
    video = next(s for s in container.streams if s.type == "video")
    out = bytearray()
    first_key = None
    for packet in container.demux(video):
        data = bytes(packet)
        if not data:
            continue
        is_key = any(
            len(nal) >= 2 and ((nal[0] >> 1) & 0x3F) in (19, 20, 21, 32, 33)
            for nal in data.split(b"\x00\x00\x01")
        )
        if first_key is None:
            if not is_key:
                continue  # start clean, on the parameter sets + idr
            first_key = float(packet.pts * packet.time_base)
        out += data
        if float(packet.pts * packet.time_base) - first_key > SECONDS:
            break
    path = target / "baby_room_2k.h265"
    path.write_bytes(bytes(out))
    print(f"wrote {path} ({len(out)} bytes)")


if __name__ == "__main__":
    main()
