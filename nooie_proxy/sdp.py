"""the reduced sdp and ice dialect spoken by nooie's ios webrtc build.

offers and answers cross the wire as ``00\\r\\n`` followed by a compact json
object rather than sdp text, and ice candidates lose their whitespace. this
module translates in both directions so aiortc only ever sees ordinary sdp.
"""

import base64
import json
import re
import secrets
import zlib
from dataclasses import dataclass
from typing import Any

from aiortc import RTCIceCandidate
from aiortc.sdp import SessionDescription, candidate_from_sdp


@dataclass(frozen=True)
class LocalIceCandidate:
    sdp: str
    sdp_mid: str
    sdp_mline_index: int
    ice_ufrag: str


def sdp_value(sdp: str, prefix: str, default: str = "") -> str:
    for line in sdp.splitlines():
        if line.startswith(prefix):
            return line[len(prefix) :]
    return default


def video_ssrc(sdp: str) -> int | None:
    for media in SessionDescription.parse(sdp).media:
        if media.kind == "video" and media.ssrc:
            return media.ssrc[0].ssrc
    return None


def local_candidates(sdp: str) -> list[LocalIceCandidate]:
    """usable ipv4 candidates worth trickling, loopback and mdns excluded."""
    chosen: list[LocalIceCandidate] = []
    ice_ufrag = sdp_value(sdp, "a=ice-ufrag:")
    sdp_mid = ""
    sdp_mline_index = -1
    for line in sdp.splitlines():
        if line.startswith("m="):
            sdp_mline_index += 1
            sdp_mid = str(sdp_mline_index)
        elif line.startswith("a=mid:"):
            sdp_mid = line[len("a=mid:") :]
        elif line.startswith("a=candidate:"):
            fields = line[len("a=candidate:") :].split()
            if len(fields) < 8:
                continue
            address, kind = fields[4], fields[7]
            if kind not in ("host", "relay") or address.endswith(".local"):
                continue
            if address.startswith("127.") or ":" in address:
                continue
            chosen.append(
                LocalIceCandidate(
                    sdp=line[len("a=") :],
                    sdp_mid=sdp_mid,
                    sdp_mline_index=sdp_mline_index,
                    ice_ufrag=ice_ufrag,
                )
            )
    # nooie's offer is bundle-only and its ios client trickles the shared
    # transport once, against the first (video) media section.
    return [item for item in chosen if item.sdp_mline_index == 0]


def compact_offer(sdp: str) -> str:
    """encode an aiortc offer as the compact object the camera expects."""
    # every preserved ios offer uses a 19-digit webrtc origin session id;
    # aiortc's is a shorter timestamp, so generate the native shape here.
    session_id = str(
        1_000_000_000_000_000_000 + secrets.randbelow(9_000_000_000_000_000_000)
    )
    cname = base64.b64encode(secrets.token_bytes(12)).decode()
    video_ssrcs = [str(secrets.randbits(32)), str(secrets.randbits(32))]
    payload = {
        "com": {
            "o": "trickle renomination",
            "I": " IP4 0.0.0.0",
            "tcc": 4,
            "p": sdp_value(sdp, "a=ice-pwd:"),
            "is": 1,
            "isc": " WMS Lo",
            "ll": 14,
            "r": "9 IN IP4 0.0.0.0",
            "iO": f" {session_id} 2 IN IP4 127.0.0.1",
            "iT": "0 0",
            "s": "actpass",
            "iG": "0 1",
            "pp": 12,
            "u": sdp_value(sdp, "a=ice-ufrag:"),
            "abs": 7,
            "ft": sdp_value(sdp, "a=fingerprint:"),
            "v": 1,
        },
        "audio": {
            "sr": 1,
            "mid": 1,
            "rm": 1,
            "sc": [str(secrets.randbits(32))],
            "pt": 96,
            "ce": cname,
            "dc": 1,
            "md": "Lo AID",
            "pts": 16000,
            "m": 9,
        },
        "video": {
            "ce": cname,
            "mid": 0,
            "pts": 90000,
            "red": 100,
            "fmtp": ["99 apt=126", "101 apt=100"],
            "rtx": [99, 101],
            "dc": 0,
            "sc": video_ssrcs,
            "md": "Lo VID",
            "pt": 126,
            "fec": 102,
            "m": 9,
            "sr": 1,
            "rm": 1,
            "fbc": 19,
            "rr": 1,
            "fb": 126,
        },
    }
    return "00\r\n" + json.dumps(payload, separators=(",", ":"))


def compact_candidate(candidate: LocalIceCandidate) -> str:
    """encode one local candidate in the numeric shape nooie's sdk emits."""
    fields = candidate.sdp.split()
    if (
        len(fields) < 8
        or not fields[0].startswith("candidate:")
        or fields[6].lower() != "typ"
    ):
        raise ValueError(f"unsupported local ICE candidate: {candidate.sdp!r}")
    kind = fields[7].lower()
    priorities = {
        "host": "2122260223",
        "srflx": "1686052607",
        "relay": "41885439",
    }
    if kind not in priorities:
        raise ValueError(f"unsupported local ICE candidate type: {kind!r}")
    foundation = zlib.crc32(
        f"{fields[0][len('candidate:'):]}:{kind}".encode()
    )
    output = [
        f"candidate:{foundation}",
        fields[1],
        fields[2].lower(),
        priorities[kind],
        fields[4],
        fields[5],
        "typ",
        kind,
    ]
    if kind in ("srflx", "relay"):
        output += ["raddr", "0.0.0.0", "rport", "0"]
    return " ".join(
        output
        + [
            "generation",
            "0",
            "ufrag",
            candidate.ice_ufrag,
            "network-id",
            "1",
            "network-cost",
            "10",
        ]
    )


def expand_candidate(value: str) -> str:
    """restore the whitespace nooie strips out of a remote ice candidate."""
    value = value.strip().removeprefix("candidate:")
    if " " in value:
        fields = value.split()
        if len(fields) < 8 or fields[6].lower() != "typ":
            raise ValueError(f"unsupported ICE candidate: {value!r}")
        return " ".join(fields)

    match = re.fullmatch(
        r"(?P<foundation>\d+)(?P<component>[12])"
        r"(?P<protocol>udp|tcp)(?P<body>.+)",
        value,
        re.IGNORECASE,
    )
    if not match:
        raise ValueError(f"unsupported compact ICE candidate: {value!r}")
    before_type, separator, after_type = match.group("body").partition("typ")
    if not separator:
        raise ValueError(f"compact ICE candidate has no type: {value!r}")
    first_dot = before_type.find(".")
    if first_dot < 0:
        raise ValueError(f"compact ICE candidate has no IPv4 address: {value!r}")

    # priority and the first octet run together, as do the last octet and the
    # port; only one split of each yields four valid octets and a valid port.
    prefix, rest = before_type[:first_dot], before_type[first_dot + 1 :]
    second_dot = rest.find(".")
    third_dot = rest.find(".", second_dot + 1)
    if second_dot < 0 or third_dot < 0:
        raise ValueError(f"compact ICE candidate has invalid IPv4: {value!r}")
    octet2, octet3 = rest[:second_dot], rest[second_dot + 1 : third_dot]
    tail = rest[third_dot + 1 :]

    parsed = None
    for head in (3, 2, 1):
        priority, octet1 = prefix[:-head], prefix[-head:]
        for last in (3, 2, 1):
            octet4, port = tail[:last], tail[last:]
            octets = (octet1, octet2, octet3, octet4)
            if (
                priority
                and port.isdigit()
                and 0 < int(port) <= 65535
                and all(part.isdigit() and int(part) <= 255 for part in octets)
            ):
                parsed = (priority, ".".join(octets), port)
                break
        if parsed:
            break
    if parsed is None:
        raise ValueError(f"cannot split compact ICE candidate: {value!r}")

    priority, address, port = parsed
    candidate_type, _, attributes = after_type.partition("raddr")
    fields = [
        match.group("foundation"),
        match.group("component"),
        match.group("protocol").lower(),
        priority,
        address,
        port,
        "typ",
        candidate_type,
    ]
    if attributes:
        related_address, _, attributes = attributes.partition("rport")
        related_port, _, attributes = attributes.partition("generation")
        generation, _, attributes = attributes.partition("ufrag")
        ufrag, _, network_cost = attributes.partition("network-cost")
        fields += [
            "raddr",
            related_address,
            "rport",
            related_port,
            "generation",
            generation,
            "ufrag",
            ufrag,
        ]
        if network_cost:
            fields += ["network-cost", network_cost]
    return " ".join(fields)


def remote_candidate(data: dict[str, Any]) -> RTCIceCandidate | None:
    """read a trickled candidate out of a signalling message."""
    value = data.get("candidate") or data.get("WebrtcCandidate")
    if not value:
        return None
    candidate = candidate_from_sdp(expand_candidate(str(value)))
    candidate.sdpMid = data.get("sdpMid") or data.get("WebrtcSdpMid")
    line = data.get("sdpMLineIndex", data.get("WebrtcSdpMLineIndex"))
    candidate.sdpMLineIndex = int(line) if line is not None else None
    return candidate


def expand_answer(value: str) -> str:
    """decode the camera's compact answer into sdp aiortc accepts."""
    if not value.startswith("00\r\n"):
        return value
    payload = json.loads(value[4:])
    common = payload["com"]

    fingerprint = str(common["ft"])
    algorithm, separator, digest = fingerprint.partition(" ")
    if separator:
        fingerprint = f"{algorithm} {digest.lstrip()}"
    elif fingerprint.startswith("sha-256"):
        fingerprint = fingerprint.replace("sha-256", "sha-256 ", 1)
    candidate = expand_candidate(str(common["ic"]))

    def transport(mid: int) -> list[str]:
        return [
            "c=IN IP4 0.0.0.0",
            "a=rtcp:9 IN IP4 0.0.0.0",
            f"a=ice-ufrag:{common['u']}",
            f"a=ice-pwd:{common['p']}",
            "a=ice-options:trickle",
            f"a=fingerprint:{fingerprint}",
            f"a=setup:{common.get('s', 'active')}",
            f"a=mid:{mid}",
            "a=sendonly",
            "a=rtcp-mux",
            f"a=candidate:{candidate}",
            (
                "a=extmap:4 http://www.ietf.org/id/"
                "draft-holmer-rmcat-transport-wide-cc-extensions-01"
            ),
        ]

    def ssrc(media: dict[str, Any]) -> str:
        value = media.get("sc", [])
        return str(value[0] if isinstance(value, list) else value)

    video, audio = payload["video"], payload["audio"]
    video_pt = int(video.get("pt", 126))
    audio_pt = int(audio.get("pt", 96))
    video_ssrc, audio_ssrc = ssrc(video), ssrc(audio)
    cname = str(video.get("ce", "nooie"))
    lines = [
        "v=0",
        "o=- 1 2 IN IP4 127.0.0.1",
        "s=-",
        "t=0 0",
        "a=group:BUNDLE 0 1",
        "a=msid-semantic: WMS myKvsVideoStream",
        f"m=video {int(video.get('m', 9))} UDP/TLS/RTP/SAVPF {video_pt}",
        *transport(int(video.get("mid", 0))),
        "a=rtcp-rsize",
        f"a=rtpmap:{video_pt} H264/{int(video.get('pts', 90000))}",
        f"a=rtcp-fb:{video_pt} goog-remb",
        f"a=rtcp-fb:{video_pt} transport-cc",
        f"a=rtcp-fb:{video_pt} nack",
        f"a=rtcp-fb:{video_pt} nack pli",
        (
            f"a=fmtp:{video_pt} level-asymmetry-allowed=1;"
            "packetization-mode=1;profile-level-id=42e01f"
        ),
        "a=msid:myKvsVideoStream myVideoTrack",
        f"a=ssrc:{video_ssrc} cname:{cname}",
        f"a=ssrc:{video_ssrc} msid:myKvsVideoStream myVideoTrack",
        f"m=audio {int(audio.get('m', 9))} UDP/TLS/RTP/SAVPF {audio_pt}",
        *transport(int(audio.get("mid", 1))),
        f"a=rtpmap:{audio_pt} AAC/{int(audio.get('pts', 16000))}",
        (
            f"a=fmtp:{audio_pt} profile-level-id=1;mode=AAC-hbr;"
            "sizelength=13;indexlength=3;indexdeltalength=3;config=1408"
        ),
        "a=msid:myKvsVideoStream myAudioTrack",
        f"a=ssrc:{audio_ssrc} cname:{audio.get('ce', cname)!s}",
        f"a=ssrc:{audio_ssrc} msid:myKvsVideoStream myAudioTrack",
        "",
    ]
    return "\r\n".join(lines)
