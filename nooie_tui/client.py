"""nooie-tui: receive a Nooie camera's live A/V stream over its WebRTC path."""

import argparse
import asyncio
import base64
import fractions
import hashlib
import hmac
import json
import os
import re
import secrets
import shlex
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator, cast

import aiohttp
import aiortc.codecs
import aiortc.rtcrtpreceiver
import aiortc.rtcrtpsender
import aiortc.rtcpeerconnection
from av import CodecContext
from av.frame import Frame
from av.packet import Packet

from . import apeman
from av.audio.resampler import AudioResampler
from aiortc import (
    AudioStreamTrack,
    RTCBundlePolicy,
    RTCConfiguration,
    RTCIceCandidate,
    RTCIceServer,
    RTCPeerConnection,
    RTCSessionDescription,
    RTCRtpSender,
)
from aiortc.codecs.base import Decoder, Encoder
from aiortc.contrib.media import MediaRecorder
from aiortc.jitterbuffer import JitterFrame
from aiortc.rtcrtpparameters import (
    RTCRtcpFeedback,
    RTCRtpCodecParameters,
    RTCRtpHeaderExtensionParameters,
)
from aiortc.rtp import RtcpRrPacket
from aiortc.sdp import SessionDescription, candidate_from_sdp
from aiortc.rtcdtlstransport import (
    RTCCertificate,
    SSL,
    generate_certificate,
)
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.hazmat.primitives import hashes


@dataclass(frozen=True)
class Config:
    app_id: str
    app_secret: str
    api_token: str
    uid: str
    request_uuid: str
    phone_code: str
    device_id: str
    model_id: str
    api_base: str = "https://app.eu.nooie.com/v2"
    ws_url: str = "wss://wss.eu.nooie.com/ws"


def load_dotenv(path: Path = Path(".env")) -> None:
    """load a small shell-style dotenv file without exposing its values."""
    if not path.is_file():
        return
    for line_number, raw in enumerate(path.read_text().splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            raise SystemExit(f"{path}:{line_number}: expected KEY=VALUE")
        key, raw_value = line.split("=", 1)
        key = key.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            raise SystemExit(f"{path}:{line_number}: invalid variable name")
        try:
            parts = shlex.split(raw_value, comments=True, posix=True)
        except ValueError as error:
            raise SystemExit(f"{path}:{line_number}: {error}") from error
        os.environ.setdefault(key, " ".join(parts) if parts else "")


def app_credentials() -> tuple[str, str]:
    app_id = os.environ.get("NOOIE_APP_ID", "")
    app_secret = os.environ.get("NOOIE_APP_SECRET", "")
    missing = []
    if not app_id:
        missing.append("NOOIE_APP_ID")
    if not app_secret:
        missing.append("NOOIE_APP_SECRET")
    if missing:
        raise SystemExit("missing environment variables: " + ", ".join(missing))
    return app_id, app_secret


def login_headers(
    app_id: str, app_secret: str, request_uuid: str
) -> dict[str, str]:
    timestamp = str(int(time.time()))
    digest = hmac.new(
        app_secret.encode(),
        f"{app_id}{timestamp}".encode(),
        hashlib.sha256,
    ).hexdigest()
    signature = base64.b64encode(digest.encode()).decode()
    return {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": os.environ.get(
            "NOOIE_USER_AGENT", "Nooie_IOS_3.7.0"
        ),
        "appid": app_id,
        "uuid": request_uuid,
        "timestamp": timestamp,
        "sign": signature,
    }


def request_headers(config: Config) -> dict[str, str]:
    timestamp = str(int(time.time()))
    content = (
        f"{config.app_id}{timestamp}{config.uid}{config.api_token}".encode()
    )
    digest = hmac.new(
        config.app_secret.encode(),
        content,
        hashlib.sha256,
    ).hexdigest()
    signature = base64.b64encode(digest.encode()).decode()
    return {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "appid": config.app_id,
        "uid": config.uid,
        "uuid": config.request_uuid,
        "timestamp": timestamp,
        "api-token": config.api_token,
        "sign": signature,
    }


def login_environment() -> tuple[str, str]:
    username = os.environ.get(
        "NOOIE_USERNAME", os.environ.get("NOOIE_EMAIL", "")
    )
    password = os.environ.get("NOOIE_PASSWORD", "")
    missing = []
    if not username:
        missing.append("NOOIE_USERNAME")
    if not password:
        missing.append("NOOIE_PASSWORD")
    if missing:
        raise SystemExit("missing environment variables: " + ", ".join(missing))
    return username, password


def local_phone_code() -> str:
    return os.environ.get("NOOIE_PHONE_CODE", str(uuid.uuid4()).upper())


async def login_config() -> Config:
    app_id, app_secret = app_credentials()
    request_uuid = os.environ.get("NOOIE_REQUEST_UUID", uuid.uuid4().hex)
    phone_code = local_phone_code()
    api_base = os.environ.get(
        "NOOIE_API_BASE", "https://app.eu.nooie.com/v2"
    ).rstrip("/")
    ws_url = os.environ.get(
        "NOOIE_WS_URL", "wss://wss.eu.nooie.com/ws"
    )
    username, password = login_environment()
    utc_offset = datetime.now().astimezone().utcoffset()
    zone = int(utc_offset.total_seconds() // 3600) if utc_offset else 0
    body = {
        "account": username,
        "country": os.environ.get("NOOIE_COUNTRY_CODE", "44"),
        "password": hashlib.md5(password.encode()).hexdigest(),
        "phone_brand": os.environ.get("NOOIE_PHONE_BRAND", "nooie-tui"),
        "phone_code": phone_code,
        "zone": zone,
    }
    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(timeout=timeout) as http:
        async with http.post(
            f"{api_base}/login/login",
            headers=login_headers(app_id, app_secret, request_uuid),
            json=body,
        ) as response:
            payload = await response.json(content_type=None)
        if response.status != 200 or payload.get("code") != 1000:
            raise RuntimeError(
                f"login failed: HTTP {response.status}, "
                f"code={payload.get('code')}, msg={payload.get('msg')!r}"
            )
        data = payload.get("data")
        if not isinstance(data, dict):
            raise RuntimeError("login response has no data object")
        config = Config(
            app_id=app_id,
            app_secret=app_secret,
            api_token=str(data["api_token"]),
            uid=str(data["uid"]),
            request_uuid=request_uuid,
            phone_code=phone_code,
            device_id="",
            model_id="",
            api_base=api_base,
            ws_url=ws_url,
        )
        device = await select_camera(http, config)
    return Config(
        **{
            **config.__dict__,
            "device_id": str(device["uuid"]),
            "model_id": str(device["type"]),
        }
    )


async def select_camera(
    http: aiohttp.ClientSession, config: Config
) -> dict[str, Any]:
    async with http.get(
        f"{config.api_base}/device/list",
        headers=request_headers(config),
        params={"page": 1, "per_page": 100},
    ) as response:
        payload = await response.json(content_type=None)
    if response.status != 200 or payload.get("code") != 1000:
        raise RuntimeError(
            f"device list failed: HTTP {response.status}, "
            f"code={payload.get('code')}, msg={payload.get('msg')!r}"
        )
    outer = payload.get("data")
    devices = outer.get("data", []) if isinstance(outer, dict) else []
    if not isinstance(devices, list):
        raise RuntimeError("device list response has an invalid shape")

    device_id = os.environ.get("NOOIE_DEVICE_ID", "")
    model_id = os.environ.get("NOOIE_MODEL_ID", "")
    candidates = [
        item
        for item in devices
        if isinstance(item, dict)
        and item.get("uuid")
        and item.get("type")
        and (not device_id or item.get("uuid") == device_id)
        and (not model_id or item.get("type") == model_id)
    ]
    online = [item for item in candidates if int(item.get("online", 0)) == 1]
    if len(online) == 1:
        selected = online[0]
    elif len(candidates) == 1:
        selected = candidates[0]
    elif not candidates:
        raise RuntimeError("no matching Nooie camera was found on this account")
    else:
        raise RuntimeError(
            "multiple matching cameras were found; set NOOIE_DEVICE_ID in .env"
        )
    print(
        f"selected {selected['type']} "
        f"({'online' if selected in online else 'offline'})",
        flush=True,
    )
    c = apeman.coords_from_device(selected)
    print(
        f"p2p coords: relay {c.hb_domain} ({c.hb_server}:{c.hb_port}) "
        f"lan {c.local_ip} wan {c.wan_ip} puuid {c.puuid} "
        f"secret<{len(c.secret)}>",
        flush=True,
    )
    return selected


async def create_session(
    http: aiohttp.ClientSession, config: Config
) -> dict[str, Any]:
    url = f"{config.api_base}/webrtcsession/user/videocall"
    async with http.post(
        url,
        headers=request_headers(config),
        json={"device_id": config.device_id},
    ) as response:
        payload = await response.json(content_type=None)
    if response.status != 200 or payload.get("code") != 1000:
        raise RuntimeError(
            f"session request failed: HTTP {response.status}, "
            f"code={payload.get('code')}, msg={payload.get('msg')!r}"
        )
    return payload["data"]


def ice_servers(session: dict[str, Any]) -> list[RTCIceServer]:
    urls = []
    for item in session.get("user_ices", []):
        url = item.get("iceurl")
        if url:
            urls.append(url)
    return [RTCIceServer(urls=url) for url in urls]


def device_ice_fields(
    session: dict[str, Any],
) -> tuple[list[str], list[str], list[str]]:
    urls: list[str] = []
    usernames: list[str] = []
    passwords: list[str] = []
    for item in session.get("device_ices", []):
        urls.append(item.get("iceurl", ""))
        usernames.append(item.get("username", ""))
        passwords.append(item.get("password", ""))
    return urls, usernames, passwords


class AacDecoder(Decoder):
    def __init__(self, codec: RTCRtpCodecParameters) -> None:
        self.codec = CodecContext.create("aac", "r")
        config = str(codec.parameters.get("config", "1408"))
        if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", config):
            self.codec.extradata = bytes.fromhex(config)
        self.time_base = fractions.Fraction(1, codec.clockRate)

    def decode(self, encoded_frame: JitterFrame) -> list[Frame]:
        data = encoded_frame.data
        if len(data) > 4 and data[:2] == b"\x00\x10":
            data = data[4:]
        packet = Packet(data)
        packet.pts = encoded_frame.timestamp
        packet.time_base = self.time_base
        return cast(list[Frame], self.codec.decode(packet))


class AacEncoder(Encoder):
    def __init__(self) -> None:
        self.codec = CodecContext.create("aac", "w")
        self.codec.bit_rate = 32000
        self.codec.format = "fltp"
        self.codec.layout = "mono"
        self.codec.sample_rate = 16000
        self.codec.time_base = fractions.Fraction(1, 16000)
        self.resampler = AudioResampler(
            format="fltp",
            layout="mono",
            rate=16000,
            frame_size=1024,
        )
        self.first_packet_pts: int | None = None

    @staticmethod
    def payload(packet: Packet) -> bytes:
        data = bytes(packet)
        # rfc 3640: one 16-bit AU header carrying a 13-bit access-unit size.
        return b"\x00\x10" + (len(data) << 3).to_bytes(2, "big") + data

    def encode(
        self, frame: Frame, force_keyframe: bool = False
    ) -> tuple[list[bytes], int | None]:
        packets: list[Packet] = []
        for resampled in self.resampler.resample(frame):
            packets.extend(self.codec.encode(resampled))
        if not packets:
            return [], None
        if self.first_packet_pts is None:
            self.first_packet_pts = packets[0].pts
        timestamp = packets[0].pts - self.first_packet_pts
        return [self.payload(packet) for packet in packets], timestamp

    def pack(self, packet: Packet) -> tuple[list[bytes], int]:
        timestamp = int(
            fractions.Fraction(packet.pts) * packet.time_base * 16000
        )
        return [self.payload(packet)], timestamp


def enable_aac() -> None:
    if not any(
        codec.mimeType.lower() == "audio/aac"
        for codec in aiortc.codecs.CODECS["audio"]
    ):
        aiortc.codecs.CODECS["audio"] = [
            RTCRtpCodecParameters(
                mimeType="audio/AAC",
                clockRate=16000,
                channels=1,
                payloadType=96,
                parameters={
                    "config": "1408",
                    "indexdeltalength": "3",
                    "indexlength": "3",
                    "mode": "AAC-hbr",
                    "profile-level-id": "1",
                    "sizelength": "13",
                },
            ),
            *[
                codec
                for codec in aiortc.codecs.CODECS["audio"]
                if codec.payloadType != 96
            ],
        ]

    original_get_decoder = aiortc.codecs.get_decoder

    def get_decoder(codec: RTCRtpCodecParameters) -> Decoder:
        if codec.mimeType.lower() == "audio/aac":
            return AacDecoder(codec)
        return original_get_decoder(codec)

    original_get_encoder = aiortc.codecs.get_encoder

    def get_encoder(codec: RTCRtpCodecParameters) -> Encoder:
        if codec.mimeType.lower() == "audio/aac":
            return AacEncoder()
        return original_get_encoder(codec)

    aiortc.codecs.get_decoder = get_decoder
    aiortc.rtcrtpreceiver.get_decoder = get_decoder
    aiortc.codecs.get_encoder = get_encoder
    aiortc.rtcrtpsender.get_encoder = get_encoder


def enable_rsa_dtls() -> None:
    def generate(cls: type[RTCCertificate]) -> RTCCertificate:
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        name = x509.Name(
            [x509.NameAttribute(x509.NameOID.COMMON_NAME, "WebRTC")]
        )
        now = datetime.now(timezone.utc)
        serial = int.from_bytes(os.urandom(8), "big") | (1 << 63)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(serial)
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=30))
            .sign(key, hashes.SHA256())
        )
        return cls(key=key, cert=certificate)

    def create_ssl_context(
        certificate: RTCCertificate, srtp_profiles: list[Any]
    ) -> SSL.Context:
        context = SSL.Context(SSL.DTLS_METHOD)
        context.set_options(SSL.OP_NO_QUERY_MTU)
        context.set_verify(
            SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
            lambda *args: True,
        )
        context.set_cipher_list(
            b"ECDHE-RSA-CHACHA20-POLY1305:"
            b"ECDHE-RSA-AES128-GCM-SHA256:"
            b"ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:@SECLEVEL=0"
        )
        context.use_certificate(certificate._cert)
        context.use_privatekey(certificate._key)
        context.set_tlsext_use_srtp(
            b":".join(profile.openssl_profile for profile in srtp_profiles)
        )
        return context

    RTCCertificate.generateCertificate = classmethod(generate)
    RTCCertificate._create_ssl_context = create_ssl_context
    if not getattr(SSL.Connection, "_nooie_mtu", False):
        original_init = SSL.Connection.__init__

        def connection_init(connection: SSL.Connection, *args: Any) -> None:
            original_init(connection, *args)
            connection.set_ciphertext_mtu(1200)
            SSL._lib.SSL_set_mtu(connection._ssl, 1200)

        SSL.Connection.__init__ = connection_init
        SSL.Connection._nooie_mtu = True
        original_accept = SSL.Connection.set_accept_state

        def set_accept_state(connection: SSL.Connection) -> None:
            original_accept(connection)
            SSL._lib.SSL_set_mtu(connection._ssl, 1200)

        SSL.Connection.set_accept_state = set_accept_state


def force_h264(peer: RTCPeerConnection) -> None:
    enable_aac()
    transport_cc = RTCRtpHeaderExtensionParameters(
        id=4,
        uri=(
            "http://www.ietf.org/id/"
            "draft-holmer-rmcat-transport-wide-cc-extensions-01"
        ),
    )
    for kind in ("audio", "video"):
        if not any(
            extension.id == transport_cc.id
            for extension in aiortc.codecs.HEADER_EXTENSIONS[kind]
        ):
            aiortc.codecs.HEADER_EXTENSIONS[kind].append(transport_cc)
    source = next(
        codec
        for codec in aiortc.codecs.CODECS["video"]
        if codec.mimeType.lower() == "video/h264"
        and codec.parameters.get("profile-level-id") == "42e01f"
    )
    h264 = RTCRtpCodecParameters(
        mimeType=source.mimeType,
        clockRate=source.clockRate,
        payloadType=126,
        rtcpFeedback=[
            *source.rtcpFeedback,
            RTCRtcpFeedback(type="transport-cc"),
        ],
        parameters=source.parameters,
    )
    aiortc.codecs.CODECS["video"] = [h264]
    transceiver = peer.addTransceiver("video", direction="recvonly")
    codecs = [
        codec
        for codec in RTCRtpSender.getCapabilities("video").codecs
        if codec.mimeType.lower() == "video/h264"
    ]
    if not codecs:
        raise RuntimeError("this aiortc build has no H.264 codec")
    transceiver.setCodecPreferences(codecs)
    audio = peer.addTransceiver("audio", direction="recvonly")
    audio_codecs = [
        codec
        for codec in RTCRtpSender.getCapabilities("audio").codecs
        if codec.mimeType.lower() == "audio/aac"
    ]
    audio.setCodecPreferences(audio_codecs)


def sdp_value(sdp: str, prefix: str, default: str = "") -> str:
    for line in sdp.splitlines():
        if line.startswith(prefix):
            return line[len(prefix) :]
    return default


def local_candidates(sdp: str) -> list[str]:
    """host/srflx candidates worth trickling, loopback and mDNS excluded."""
    chosen = []
    for line in sdp.splitlines():
        if not line.startswith("a=candidate:"):
            continue
        fields = line[len("a=candidate:") :].split()
        if len(fields) < 8:
            continue
        address, kind = fields[4], fields[7]
        if kind not in ("host", "srflx") or address.endswith(".local"):
            continue
        if address.startswith("127.") or ":" in address:
            continue
        chosen.append(line[len("a=") :])
    return chosen


def compact_candidate(candidate: str) -> str:
    if candidate.startswith("candidate:"):
        candidate = candidate[len("candidate:") :]
    return candidate.replace(" ", "")


def compact_sdp_offer(sdp: str) -> str:
    """encode the reduced SDP dialect used by the Nooie iOS WebRTC build."""
    ice_ufrag = sdp_value(sdp, "a=ice-ufrag:")
    ice_pwd = sdp_value(sdp, "a=ice-pwd:")
    fingerprint = sdp_value(sdp, "a=fingerprint:")
    # o= encoding: real session id, session version 2.
    origin = sdp_value(sdp, "o=").split()
    session_id = origin[1] if len(origin) > 1 else str(secrets.randbits(62))
    cname = base64.b64encode(secrets.token_bytes(12)).decode()
    video_ssrc = str(secrets.randbits(32))
    video_rtx_ssrc = str(secrets.randbits(32))
    audio_ssrc = str(secrets.randbits(32))

    common: dict[str, Any] = {
        "o": "tricklerenomination",
        "I": "IP40.0.0.0",
        "tcc": 4,
        "p": ice_pwd,
        "is": 1,
        "isc": "WMSLo",
        "ll": 14,
        "r": "9INIP40.0.0.0",
        "iO": f"{session_id}2INIP4127.0.0.1",
        "iT": "00",
        "s": "actpass",
        "iG": "01",
        "pp": 12,
        "u": ice_ufrag,
        "abs": 7,
        "ft": fingerprint.replace(" ", ""),
        "v": 1,
    }
    payload = {
        "com": common,
        "audio": {
            "sr": 1,
            "mid": 1,
            "rm": 1,
            "sc": [audio_ssrc],
            "pt": 96,
            "ce": cname,
            "dc": 1,
            "md": "LoAID",
            "pts": 16000,
            "m": 9,
        },
        "video": {
            "ce": cname,
            "mid": 0,
            "pts": 90000,
            "red": 100,
            "fmtp": ["99apt=126", "101apt=100"],
            "rtx": [99, 101],
            "dc": 0,
            "sc": [video_ssrc, video_rtx_ssrc],
            "md": "LoVID",
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
    # the offer prefixes the compact JSON with two zeros and a bare LF ("00\n").
    return "00\n" + json.dumps(payload, separators=(",", ":"))


def expand_compact_candidate(value: str) -> str:
    match = re.fullmatch(
        r"(?P<foundation>\d+)(?P<component>[12])"
        r"(?P<protocol>udp|tcp)(?P<body>.+)",
        value,
        re.IGNORECASE,
    )
    if not match:
        raise ValueError(f"unsupported compact ICE candidate: {value!r}")
    body = match.group("body")
    before_type, separator, after_type = body.partition("typ")
    if not separator:
        raise ValueError(f"compact ICE candidate has no type: {value!r}")
    first_dot = before_type.find(".")
    if first_dot < 0:
        raise ValueError(f"compact ICE candidate has no IPv4 address: {value!r}")

    prefix = before_type[:first_dot]
    rest = before_type[first_dot + 1 :]
    second_dot = rest.find(".")
    third_dot = rest.find(".", second_dot + 1)
    if second_dot < 0 or third_dot < 0:
        raise ValueError(f"compact ICE candidate has invalid IPv4: {value!r}")
    octet2 = rest[:second_dot]
    octet3 = rest[second_dot + 1 : third_dot]
    tail = rest[third_dot + 1 :]

    parsed: tuple[str, str, str, str] | None = None
    for first_length in (3, 2, 1):
        priority = prefix[:-first_length]
        octet1 = prefix[-first_length:]
        if not priority:
            continue
        for last_length in (3, 2, 1):
            octet4 = tail[:last_length]
            port = tail[last_length:]
            octets = (octet1, octet2, octet3, octet4)
            if (
                port
                and all(part.isdigit() and int(part) <= 255 for part in octets)
                and port.isdigit()
                and 0 < int(port) <= 65535
            ):
                parsed = (
                    priority,
                    ".".join(octets),
                    port,
                    after_type,
                )
                break
        if parsed is not None:
            break
    if parsed is None:
        raise ValueError(f"cannot split compact ICE candidate: {value!r}")

    priority, address, port, suffix = parsed
    candidate_type, _, attributes = suffix.partition("raddr")
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
        fields.extend(
            [
                "raddr",
                related_address,
                "rport",
                related_port,
                "generation",
                generation,
                "ufrag",
                ufrag,
            ]
        )
        if network_cost:
            fields.extend(["network-cost", network_cost])
    return " ".join(fields)


def compact_sdp_answer(value: str) -> str:
    """decode Nooie's reduced answer into SDP accepted by aiortc."""
    if not value.startswith("00\r\n"):
        return value
    payload = json.loads(value[4:])
    common = payload["com"]

    fingerprint = str(common["ft"])
    fingerprint = fingerprint.replace("sha-256", "sha-256 ", 1)
    candidate = expand_compact_candidate(str(common["ic"]))
    ice_ufrag = str(common["u"])
    ice_pwd = str(common["p"])
    setup = str(common.get("s", "active"))

    session_lines = [
        "v=0",
        "o=- 1 2 IN IP4 127.0.0.1",
        "s=-",
        "t=0 0",
        "a=group:BUNDLE 0 1",
        "a=msid-semantic: WMS myKvsVideoStream",
    ]

    def transport_lines(mid: int) -> list[str]:
        return [
            "c=IN IP4 0.0.0.0",
            "a=rtcp:9 IN IP4 0.0.0.0",
            f"a=ice-ufrag:{ice_ufrag}",
            f"a=ice-pwd:{ice_pwd}",
            "a=ice-options:trickle",
            f"a=fingerprint:{fingerprint}",
            f"a=setup:{setup}",
            f"a=mid:{mid}",
            "a=sendonly",
            "a=rtcp-mux",
            f"a=candidate:{candidate}",
            (
                "a=extmap:4 http://www.ietf.org/id/"
                "draft-holmer-rmcat-transport-wide-cc-extensions-01"
            ),
        ]

    video = payload["video"]
    video_pt = int(video.get("pt", 126))
    video_ssrcs = video.get("sc", [])
    if not isinstance(video_ssrcs, list):
        video_ssrcs = [video_ssrcs]
    video_ssrc = str(video_ssrcs[0])
    video_cname = str(video.get("ce", "nooie"))
    video_lines = [
        f"m=video {int(video.get('m', 9))} UDP/TLS/RTP/SAVPF {video_pt}",
        *transport_lines(int(video.get("mid", 0))),
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
        f"a=ssrc:{video_ssrc} cname:{video_cname}",
        (
            f"a=ssrc:{video_ssrc} "
            "msid:myKvsVideoStream myVideoTrack"
        ),
    ]

    audio = payload["audio"]
    audio_pt = int(audio.get("pt", 96))
    audio_ssrcs = audio.get("sc", [])
    if not isinstance(audio_ssrcs, list):
        audio_ssrcs = [audio_ssrcs]
    audio_ssrc = str(audio_ssrcs[0])
    audio_cname = str(audio.get("ce", video_cname))
    audio_lines = [
        f"m=audio {int(audio.get('m', 9))} UDP/TLS/RTP/SAVPF {audio_pt}",
        *transport_lines(int(audio.get("mid", 1))),
        f"a=rtpmap:{audio_pt} AAC/{int(audio.get('pts', 16000))}",
        (
            f"a=fmtp:{audio_pt} profile-level-id=1;mode=AAC-hbr;"
            "sizelength=13;indexlength=3;indexdeltalength=3;config=1408"
        ),
        "a=msid:myKvsVideoStream myAudioTrack",
        f"a=ssrc:{audio_ssrc} cname:{audio_cname}",
        (
            f"a=ssrc:{audio_ssrc} "
            "msid:myKvsVideoStream myAudioTrack"
        ),
    ]
    return "\r\n".join([*session_lines, *video_lines, *audio_lines, ""])


def signalling_offer(
    config: Config, session: dict[str, Any], sdp: str
) -> tuple[str, str, dict[str, Any]]:
    call_uuid = str(uuid.uuid4()).upper()
    call_id = f"iOS_{call_uuid[:12]}"
    message_id = 1000
    urls, usernames, passwords = device_ice_fields(session)
    envelope = {
        "method": "service.SdpOffer",
        "msg_id": f"{call_id}_{message_id + 1}",
        "ver": "1.0",
        "time": int(time.time()),
        "origin": 1,
        "uuid": config.device_id,
        "device_model": config.model_id,
        "data": {
            "SessionId": session["session_id"],
            "call_id": call_id,
            "IceUrl": urls,
            "IceUsername": usernames,
            "IcePassword": passwords,
            "WebrtcSdp": sdp,
            "Action": 2,
            "TrickleICE": 0,
            "Timestamp": 0,
            "CodecMode": 1,
            "Quality": 1,
            "EnableSpeaker": 0,
            "EnableMic": 0,
            "Prepare": 0,
            "dtlsTimeOut": 2000,
            "onlyRelay": 0,
        },
    }
    return call_id, call_uuid, envelope


def signalling_switch(
    config: Config,
    session: dict[str, Any],
    call_id: str,
    call_uuid: str,
) -> dict[str, Any]:
    return {
        "method": "service.Switch",
        "msg_id": f"{call_id}_1002",
        "ver": "1.0",
        "tme": int(time.time()),
        "origin": 1,
        "uuid": config.device_id,
        "device_model": config.model_id,
        "data": {
            "SessionId": session["session_id"],
            "call_id": call_id,
            "Action": 0,
        },
    }


def signalling_candidate(
    config: Config,
    session: dict[str, Any],
    call_id: str,
    candidate: str,
) -> dict[str, Any]:
    return {
        "method": "service.IceCandidate",
        "msg_id": f"{str(uuid.uuid4()).upper()}_1002",
        "ver": "1.0",
        "time": int(time.time()),
        "origin": 1,
        "uuid": config.device_id,
        "device_model": config.model_id,
        "data": {
            "SessionId": session["session_id"],
            "call_id": call_id,
            "WebrtcCandidate": "candidate:" + compact_candidate(candidate),
            "WebrtcSdpMLineIndex": 0,
            "WebrtcSdpMid": "0",
            "nsType": "",
            "type": "candidate",
        },
    }


def signalling_close(
    config: Config,
    session: dict[str, Any],
    call_id: str,
    call_uuid: str,
) -> dict[str, Any]:
    return {
        "method": "service.Close",
        "msg_id": f"{call_id}_1003",
        "ver": "1.0",
        "time": int(time.time()),
        "origin": 1,
        "uuid": config.device_id,
        "device_model": config.model_id,
        "data": {
            "SessionId": session["session_id"],
            "call_id": call_id,
        },
    }


def nested_dicts(value: Any) -> Iterator[dict[str, Any]]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from nested_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from nested_dicts(child)


def matching_signal(
    message: Any, call_id: str, session_id: str
) -> dict[str, Any] | None:
    # the camera answer reuses the offer msg_id and carries SessionId but no
    # call_id; device ICE events carry call_id. accept either identifier.
    for item in nested_dicts(message):
        method = str(item.get("method", ""))
        if "SdpAnswer" not in method and "IceCandidate" not in method:
            continue
        for data in nested_dicts(item.get("data")):
            if data.get("call_id") == call_id or (
                session_id and data.get("SessionId") == session_id
            ):
                return {"method": method, "data": data}
    return None


def signal_summary(message: Any) -> str:
    methods = sorted(
        {
            str(item["method"])
            for item in nested_dicts(message)
            if item.get("method")
        }
    )
    top_keys = sorted(message) if isinstance(message, dict) else []
    status = ""
    if isinstance(message, dict) and "code" in message:
        status = (
            f", code={message.get('code')!r}, "
            f"method={message.get('method')!r}, msg={message.get('msg')!r}, "
            f"data_type={type(message.get('data')).__name__}"
        )
    switch_values = []
    if any("Switch" in method for method in methods):
        for item in nested_dicts(
            message.get("data") if isinstance(message, dict) else None
        ):
            for key, value in item.items():
                if isinstance(value, (bool, int, float)):
                    switch_values.append(f"{key}={value}")
        if switch_values:
            status += ", values=" + "/".join(sorted(set(switch_values)))
    return f"keys={top_keys}, methods={methods}{status}"


def sdp_media_summary(sdp: str) -> str:
    sections = []
    for line in sdp.splitlines():
        if line.startswith("m="):
            sections.append(line.split(maxsplit=1)[0])
        elif line.startswith("a=mid:") and sections:
            sections[-1] += f"/{line[6:]}"
        elif line in {
            "a=inactive",
            "a=recvonly",
            "a=sendonly",
            "a=sendrecv",
        } and sections:
            sections[-1] += f"/{line[2:]}"
    return ", ".join(sections)


def sdp_codec_summary(sdp: str) -> str:
    codecs = []
    media = ""
    for line in sdp.splitlines():
        if line.startswith("m="):
            media = line[2:].split(maxsplit=1)[0]
        elif line.startswith("a=rtpmap:"):
            codecs.append(f"{media}:{line[9:]}")
    return ", ".join(codecs)


def video_ssrc(sdp: str) -> int | None:
    description = SessionDescription.parse(sdp)
    for media in description.media:
        if media.kind == "video" and media.ssrc:
            return media.ssrc[0].ssrc
    return None


async def activate_video(peer: RTCPeerConnection) -> None:
    if peer.remoteDescription is None:
        return
    ssrc = video_ssrc(peer.remoteDescription.sdp)
    if ssrc is None:
        return
    for transceiver in peer.getTransceivers():
        if transceiver.kind == "video":
            await transceiver.receiver._send_rtcp(
                RtcpRrPacket(
                    ssrc=transceiver.sender._ssrc,
                    reports=[],
                )
            )
            await transceiver.receiver._send_rtcp_pli(ssrc)


def remote_candidate(data: dict[str, Any]) -> RTCIceCandidate | None:
    # device trickle arrives as event.IceCandidate with a compact, space-free
    # WebrtcCandidate; ordinary answers use a normal "candidate" field.
    candidate_sdp = data.get("candidate") or data.get("WebrtcCandidate")
    if not candidate_sdp:
        return None
    candidate_sdp = str(candidate_sdp)
    if candidate_sdp.startswith("candidate:"):
        candidate_sdp = candidate_sdp[len("candidate:") :]
    if " " not in candidate_sdp:
        candidate_sdp = expand_compact_candidate(candidate_sdp)
    candidate = candidate_from_sdp(candidate_sdp)
    candidate.sdpMid = data.get("sdpMid") or data.get("WebrtcSdpMid")
    line = data.get("sdpMLineIndex")
    if line is None:
        line = data.get("WebrtcSdpMLineIndex")
    candidate.sdpMLineIndex = int(line) if line is not None else None
    return candidate


async def receive(
    config: Config, output: Path, duration: float
) -> None:
    enable_rsa_dtls()
    # publish our nat mapping on the p2p network so the camera can reach us.
    # `reg` keeps its udp socket open for the duration of the call.
    print("registering on the p2p network", flush=True)
    reg = await asyncio.to_thread(apeman.register, config.uid)
    print(
        f"registered {reg.uid}: wan {reg.wan_ip}:{reg.wan_port} "
        f"lan {reg.lan_ip}:{reg.lan_port}",
        flush=True,
    )
    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(timeout=timeout) as http:
        ws_headers = {
            "uid": config.uid,
            "appid": config.app_id,
            "api_token": os.environ.get(
                "NOOIE_WS_API_TOKEN", config.api_token
            ),
            "phone_code": config.phone_code,
        }
        print("connecting to Nooie signalling WebSocket", flush=True)
        async with http.ws_connect(
            config.ws_url, headers=ws_headers, heartbeat=20
        ) as websocket:
            print("creating Nooie WebRTC session", flush=True)
            session = await create_session(http, config)
            peer = RTCPeerConnection(
                RTCConfiguration(
                    iceServers=ice_servers(session),
                    bundlePolicy=RTCBundlePolicy.MAX_BUNDLE,
                )
            )
            recorder = MediaRecorder(str(output))
            recorder_start: asyncio.Task[None] | None = None
            connected = asyncio.Event()

            async def start_recorder() -> None:
                await asyncio.sleep(0.5)
                await recorder.start()

            @peer.on("track")
            def on_track(track: Any) -> None:
                nonlocal recorder_start
                print(f"received {track.kind} track", flush=True)
                recorder.addTrack(track)
                if recorder_start is None:
                    recorder_start = asyncio.create_task(start_recorder())

            @peer.on("connectionstatechange")
            async def on_connectionstatechange() -> None:
                print(f"peer state: {peer.connectionState}", flush=True)
                if peer.connectionState == "connected":
                    connected.set()

            call_id = call_uuid = ""
            try:
                force_h264(peer)
                offer = await peer.createOffer()
                await peer.setLocalDescription(offer)
                if peer.localDescription is None:
                    raise RuntimeError(
                        "aiortc did not produce a local description"
                    )
                call_id, call_uuid, frame = signalling_offer(
                    config,
                    session,
                    compact_sdp_offer(peer.localDescription.sdp),
                )
                await websocket.send_json(frame, dumps=lambda value: json.dumps(
                    value, separators=(",", ":")
                ))
                for local_candidate in local_candidates(
                    peer.localDescription.sdp
                ):
                    await websocket.send_json(
                        signalling_candidate(
                            config,
                            session,
                            call_id,
                            local_candidate,
                        ),
                        dumps=lambda value: json.dumps(
                            value, separators=(",", ":")
                        ),
                    )
                print("offer sent; waiting for camera answer", flush=True)
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline and not connected.is_set():
                    remaining = max(0.1, deadline - time.monotonic())
                    try:
                        async with asyncio.timeout(remaining):
                            message = await websocket.receive()
                    except TimeoutError:
                        break
                    if message.type == aiohttp.WSMsgType.TEXT:
                        try:
                            value = json.loads(message.data)
                        except json.JSONDecodeError:
                            print(
                                "received non-JSON WebSocket text", flush=True
                            )
                            continue
                        print(
                            "WebSocket message: " + signal_summary(value),
                            flush=True,
                        )
                        signal = matching_signal(
                            value, call_id, session["session_id"]
                        )
                        if signal is None:
                            continue
                        data = signal["data"]
                        if "SdpAnswer" in signal["method"]:
                            ret = int(data.get("Ret", 0))
                            if ret != 0:
                                raise RuntimeError(
                                    f"camera rejected the call with Ret={ret} "
                                    f"(data={json.dumps(data)})"
                                )
                            answer_sdp = data.get("WebrtcSdp")
                            if answer_sdp:
                                answer_sdp = compact_sdp_answer(
                                    str(answer_sdp)
                                )
                                print(
                                    "SDP media: offer="
                                    + sdp_media_summary(
                                        peer.localDescription.sdp
                                    )
                                    + ", answer="
                                    + sdp_media_summary(answer_sdp),
                                    flush=True,
                                )
                                print(
                                    "SDP codecs: offer="
                                    + sdp_codec_summary(
                                        peer.localDescription.sdp
                                    )
                                    + ", answer="
                                    + sdp_codec_summary(answer_sdp),
                                    flush=True,
                                )
                                await peer.setRemoteDescription(
                                    RTCSessionDescription(
                                        sdp=answer_sdp, type="answer"
                                    )
                                )
                                print("camera answer accepted", flush=True)
                                await asyncio.wait_for(
                                    connected.wait(), timeout=10
                                )
                        elif "IceCandidate" in signal["method"]:
                            candidate = remote_candidate(data)
                            if candidate is not None:
                                await peer.addIceCandidate(candidate)
                    elif message.type in {
                        aiohttp.WSMsgType.CLOSED,
                        aiohttp.WSMsgType.CLOSE,
                        aiohttp.WSMsgType.ERROR,
                    }:
                        raise RuntimeError(
                            "signalling WebSocket closed: "
                            f"type={message.type.name}, data={message.data!r}, "
                            f"extra={message.extra!r}"
                        )

                if not connected.is_set():
                    raise RuntimeError(
                        "camera did not return an SDP answer within 30 seconds"
                    )
                await websocket.send_json(
                    signalling_switch(
                        config, session, call_id, call_uuid
                    ),
                    dumps=lambda value: json.dumps(
                        value, separators=(",", ":")
                    ),
                )
                print("live stream requested", flush=True)
                try:
                    async with asyncio.timeout(2):
                        switch_message = await websocket.receive()
                    if switch_message.type == aiohttp.WSMsgType.TEXT:
                        value = json.loads(switch_message.data)
                        print(
                            "switch response: " + signal_summary(value),
                            flush=True,
                        )
                except (TimeoutError, json.JSONDecodeError):
                    pass
                await activate_video(peer)
                print("video receiver activated", flush=True)
                print(
                    f"recording {duration:g} seconds to {output}", flush=True
                )
                recording_deadline = time.monotonic() + duration
                while time.monotonic() < recording_deadline:
                    remaining = recording_deadline - time.monotonic()
                    try:
                        async with asyncio.timeout(min(1, remaining)):
                            status_message = await websocket.receive()
                    except TimeoutError:
                        continue
                    if status_message.type == aiohttp.WSMsgType.TEXT:
                        try:
                            value = json.loads(status_message.data)
                        except json.JSONDecodeError:
                            continue
                        print(
                            "WebSocket message: "
                            + signal_summary(value),
                            flush=True,
                        )
                        if any(
                            "SwitchResp" in method
                            for method in {
                                str(item.get("method", ""))
                                for item in nested_dicts(value)
                            }
                        ):
                            await activate_video(peer)
                inbound = [
                    report
                    for report in (await peer.getStats()).values()
                    if report.type == "inbound-rtp"
                ]
                print(
                    "inbound RTP: "
                    + ", ".join(
                        f"{report.kind}={report.packetsReceived} packets/"
                        f"{report.bytesReceived} bytes"
                        for report in inbound
                    ),
                    flush=True,
                )
            finally:
                # always release the session so the camera's small P2P
                # connection pool does not fill with half-open calls.
                if call_id and not websocket.closed:
                    try:
                        await websocket.send_json(
                            signalling_close(
                                config, session, call_id, call_uuid
                            ),
                            dumps=lambda value: json.dumps(
                                value, separators=(",", ":")
                            ),
                        )
                    except (aiohttp.ClientError, ConnectionError):
                        pass
                if recorder_start is not None:
                    await recorder_start
                await recorder.stop()
                await peer.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="receive live A/V from your Nooie camera over its WebRTC path"
    )
    parser.add_argument(
        "--output", type=Path, default=Path("nooie.mp4"), help="recording path"
    )
    parser.add_argument(
        "--duration", type=float, default=30, help="seconds to record"
    )
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="validate required environment variables without connecting",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    load_dotenv()
    if args.check_config:
        login_environment()
        app_credentials()
        print("configuration is complete")
        return
    config = asyncio.run(login_config())
    if args.output.exists():
        raise SystemExit(f"refusing to overwrite {args.output}")
    asyncio.run(receive(config, args.output, args.duration))


if __name__ == "__main__":
    main()
