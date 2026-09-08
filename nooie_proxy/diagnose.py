"""--diagnose: one short call, observed passively, reported honestly.

consolidates the 2026-09-08 spike scripts. observation is passive by
design: wrappers on the rtp/rtcp path killed calls during the spike, so
this module only wraps the answer translation and the decode path, and
reads aiortc state without touching it.
"""

import argparse
import asyncio
import collections
import json
import os
import signal
import time
from typing import Any

from . import codec, h265, rtc, sdp
from .env import log

SECRETS = ("u", "p", "ft")
H264_NAMES = {1: "slice", 5: "IDR", 6: "SEI", 7: "SPS", 8: "PPS", 9: "AUD"}
H265_NAMES = {
    0: "TRAIL_N", 1: "TRAIL_R", 19: "IDR_W_RADL", 20: "IDR_N_LP",
    21: "CRA", 32: "VPS", 33: "SPS", 34: "PPS", 35: "AUD", 39: "SEI",
}
WARNING = (
    "WARNING: Nooie holds one signalling connection per install. Running "
    "--diagnose while the Home Assistant integration is active takes down "
    "its stream; disable the config entry first."
)


def redact_answer(value: str) -> str:
    """the compact answer with its session secrets replaced."""
    if not value.startswith("00\r\n"):
        return value
    try:
        payload = json.loads(value[4:])
    except json.JSONDecodeError:
        return value
    common = payload.get("com", {})
    for secret in SECRETS:
        if secret in common:
            common[secret] = "REDACTED"
    return "00\r\n" + json.dumps(payload, separators=(",", ":"))


def count_nals(counters: dict[str, collections.Counter], data: bytes) -> None:
    """count every nal unit under both readings; a mislabelled stream shows
    up as one histogram that makes sense and one that does not."""
    for nal in data.split(b"\x00\x00\x01"):
        if len(nal) >= 2:
            counters["h264"][nal[0] & 0x1F] += 1
            counters["h265"][h265.nal_type(nal[0])] += 1


class Observer:
    """what one call showed, gathered without disturbing it."""

    def __init__(self) -> None:
        self.answer: str | None = None
        self.tracks: dict[str, dict[str, float]] = {}
        self.keyframes = 0
        self.nals: dict[str, collections.Counter] = {
            "h264": collections.Counter(),
            "h265": collections.Counter(),
        }
        self.ssrcs: dict[str, set[int]] = {}
        self.ice: dict[str, Any] | None = None
        self.peer: Any = None
        self.started = time.monotonic()

    def install(self) -> None:
        observer = self
        import nooie_proxy.stream as stream_module

        original_expand = sdp.expand_answer

        def expand_answer(value: str) -> str:
            observer.answer = value
            return original_expand(value)

        sdp.expand_answer = expand_answer

        original_peer = stream_module.RTCPeerConnection

        def peer_factory(*args: Any, **kwargs: Any) -> Any:
            peer = original_peer(*args, **kwargs)
            observer.peer = peer
            return peer

        stream_module.RTCPeerConnection = peer_factory

        original_decode = rtc.Verbatim.decode

        def decode(verbatim: Any, encoded_frame: Any) -> list[Any]:
            packets = original_decode(verbatim, encoded_frame)
            kind = "audio" if verbatim.audio else "video"
            track = observer.tracks.setdefault(
                kind,
                {"packets": 0, "bytes": 0,
                 "first": round(time.monotonic() - observer.started, 1)},
            )
            for packet in packets:
                track["packets"] += 1
                track["bytes"] += packet.size
                if kind == "video":
                    count_nals(observer.nals, bytes(packet))
                    if packet.is_keyframe:
                        observer.keyframes += 1
            return packets

        rtc.Verbatim.decode = decode

    def sample(self) -> None:
        """read-only look at aiortc's state; never call into it."""
        peer = self.peer
        if peer is None:
            return
        for transceiver in peer.getTransceivers():
            receiver = transceiver.receiver
            active = getattr(receiver, "_RTCRtpReceiver__active_ssrc", {})
            if active:
                self.ssrcs.setdefault(transceiver.kind, set()).update(active)
            transport = receiver.transport.transport
            connection = getattr(transport, "_connection", None)
            nominated = getattr(connection, "_nominated", {}) if connection else {}
            for pair in nominated.values():
                remote = pair.remote_candidate
                self.ice = {
                    "remote": f"{remote.host}:{remote.port}",
                    "type": remote.type,
                }


def build_report(observer: Observer, elapsed: float, raw: bool) -> dict[str, Any]:
    answer = observer.answer or ""
    chosen = codec.video_codec()
    names = H265_NAMES if chosen == "h265" else H264_NAMES
    try:
        announced_ssrc = (
            sdp.video_ssrc(sdp.expand_answer(answer)) if answer else None
        )
    except Exception:  # noqa: BLE001 — a malformed answer must not sink the report
        announced_ssrc = None
    return {
        "codec": chosen,
        "answer": (answer if raw else redact_answer(answer)) or None,
        "announced": {
            "video_pt": sdp.answer_video_pt(answer) if answer else None,
            "video_ssrc": announced_ssrc,
        },
        "received_ssrcs": {
            kind: sorted(values) for kind, values in observer.ssrcs.items()
        },
        "tracks": {
            kind: {
                "packets": int(track["packets"]),
                "kbps": int(track["bytes"] * 8 / max(elapsed, 1) / 1000),
                "first_after_s": track["first"],
            }
            for kind, track in observer.tracks.items()
        },
        "keyframes": observer.keyframes,
        "nal_histogram": {
            f"{kind} {names.get(kind, '?')}": count
            for kind, count in sorted(observer.nals[chosen].items())
        },
        "ice": None if observer.ice is None else {
            **observer.ice,
            "verdict": "LAN" if observer.ice["type"] == "host" else "relay/cloud",
        },
        "elapsed_s": round(elapsed, 1),
    }


async def run(argv: list[str]) -> None:
    parser = argparse.ArgumentParser(prog="nooie-proxy --diagnose")
    parser.add_argument("--diagnose", action="store_true")
    parser.add_argument("--seconds", type=int, default=30)
    parser.add_argument("--raw", action="store_true")
    parser.add_argument("--json", action="store_true")
    options = parser.parse_args(argv)
    log(WARNING)
    os.environ["NOOIE_OUTPUT"] = os.devnull
    observer = Observer()
    observer.install()

    async def sampler() -> None:
        while True:
            observer.sample()
            await asyncio.sleep(1)

    async def alarm() -> None:
        # sigterm is the one ending the upstream unwinds cleanly: the call
        # is released in the camera's small pool instead of lingering.
        await asyncio.sleep(options.seconds)
        signal.raise_signal(signal.SIGTERM)

    sampling = asyncio.create_task(sampler())
    ringing = asyncio.create_task(alarm())
    from .service import serve  # late import; service imports us lazily too

    try:
        await serve()
    finally:
        sampling.cancel()
        ringing.cancel()
        report = build_report(
            observer, time.monotonic() - observer.started, options.raw
        )
        if options.json:
            print(json.dumps(report, indent=2))
        else:
            for key, value in report.items():
                print(f"{key}: {value}")
