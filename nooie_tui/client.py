"""nooie-tui: receive a Nooie camera's live A/V stream over its WebRTC path."""

import argparse
import asyncio
import base64
import fractions
from getpass import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import shlex
import sys
import time
import uuid
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from signal import SIGINT
from typing import Any, Iterator, cast
from urllib.parse import urlsplit

import aiohttp
import aioice.ice
import aiortc.codecs
import aiortc.rtcpeerconnection
import aiortc.rtcrtpreceiver
import aiortc.rtcrtpsender
from aiortc import (
    RTCBundlePolicy,
    RTCConfiguration,
    RTCIceCandidate,
    RTCIceServer,
    RTCPeerConnection,
    RTCRtpSender,
    RTCSessionDescription,
)
from aiortc.codecs.base import Decoder, Encoder
from aiortc.contrib.media import MediaRecorder
from aiortc.jitterbuffer import JitterFrame
from aiortc.rtcdtlstransport import (
    SSL,
    RTCCertificate,
)
from aiortc.rtcrtpparameters import (
    RTCRtcpFeedback,
    RTCRtpCodecParameters,
    RTCRtpHeaderExtensionParameters,
)
from aiortc.rtp import RtcpRrPacket
from aiortc.sdp import SessionDescription, candidate_from_sdp
from av import CodecContext, InvalidDataError
from av.audio.resampler import AudioResampler
from av.frame import Frame
from av.packet import Packet
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

from . import apeman
from .thing import (
    ThingClient,
    load_or_create_device_id,
    mqtt_presence,
    normalize_device_id,
    thing_app_from_environment,
)

DEFAULT_APP_ID = "4adcd2139621b1ef"
DEFAULT_APP_SECRET = "9e03f0b14adcd2139621b1ef984b2ac0"


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


@dataclass
class SignallingCall:
    """Per-call identifiers used by Nooie's iOS signalling implementation."""

    call_uuid: str = field(
        default_factory=lambda: str(uuid.uuid4()).upper()
    )
    message_id: int = 1000

    @property
    def call_id(self) -> str:
        return f"iOS_{self.call_uuid[:12]}"

    def next_message_id(self, *, call_scoped: bool = False) -> str:
        self.message_id += 1
        prefix = (
            self.call_id
            if call_scoped
            else f"iOS_{str(uuid.uuid4()).upper()}"
        )
        return f"{prefix}_{self.message_id}"


@dataclass(frozen=True)
class LocalIceCandidate:
    sdp: str
    sdp_mid: str
    sdp_mline_index: int
    ice_ufrag: str


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
    """Return Nooie's shared app credentials, allowing rotation overrides."""
    return (
        os.environ.get("NOOIE_APP_ID") or DEFAULT_APP_ID,
        os.environ.get("NOOIE_APP_SECRET") or DEFAULT_APP_SECRET,
    )


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
        "User-Agent": os.environ.get(
            "NOOIE_USER_AGENT", "Nooie_IOS_3.7.0"
        ),
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


def websocket_origin(url: str) -> str:
    """Match SocketRocket's native ws→http / wss→https Origin mapping."""
    parsed = urlsplit(url)
    schemes = {"ws": "http", "wss": "https"}
    if parsed.scheme not in schemes or not parsed.netloc:
        raise ValueError("Nooie WebSocket URL is invalid")
    return f"{schemes[parsed.scheme]}://{parsed.netloc}"


def websocket_json_dumps(value: Any) -> str:
    """Match NSJSONSerialization's pretty-printed signalling wire format."""

    def render(item: Any, level: int) -> str:
        indentation = "  " * level
        child_indentation = "  " * (level + 1)
        if isinstance(item, dict):
            if not item:
                return "{\n\n" + indentation + "}"
            fields = []
            for key in sorted(item):
                encoded_key = json.dumps(str(key), ensure_ascii=False)
                fields.append(
                    child_indentation
                    + encoded_key
                    + " : "
                    + render(item[key], level + 1)
                )
            return "{\n" + ",\n".join(fields) + "\n" + indentation + "}"
        if isinstance(item, (list, tuple)):
            if not item:
                return "[\n\n" + indentation + "]"
            fields = [
                child_indentation + render(child, level + 1)
                for child in item
            ]
            return "[\n" + ",\n".join(fields) + "\n" + indentation + "]"
        encoded = json.dumps(item, ensure_ascii=False, separators=(",", ":"))
        return encoded.replace("/", r"\/")

    return render(value, 0)


def login_request_body(
    username: str,
    password: str,
    phone_code: str,
    country_code: str,
    zone: int,
) -> dict[str, Any]:
    """Build the credential-login body used by the current Nooie iOS app."""
    return {
        "account": username,
        "country": country_code,
        "password": hashlib.md5(password.encode()).hexdigest(),
        "phone_brand": os.environ.get(
            "NOOIE_LOGIN_PHONE_BRAND",
            "iPad Pro 12.9-in. 3rd gen",
        ),
        "phone_code": phone_code,
        "zone": zone,
    }


def client_registration(config: Config) -> dict[str, Any]:
    """Build the install metadata posted by Nooie after a successful login."""
    utc_offset = datetime.now().astimezone().utcoffset()
    zone = int(utc_offset.total_seconds() // 3600) if utc_offset else 0
    return {
        "phone_brand": os.environ.get("NOOIE_PHONE_BRAND", "Apple"),
        "zone": zone,
        "phone_version": os.environ.get("NOOIE_PHONE_VERSION", "26.5"),
        "app_version": os.environ.get("NOOIE_APP_VERSION", "3.7.0"),
        "phone_screen": os.environ.get(
            "NOOIE_PHONE_SCREEN", "[1470, 956]"
        ),
        "device_type": int(os.environ.get("NOOIE_DEVICE_TYPE", "2")),
        "phone_code": config.phone_code,
        "package_name": os.environ.get(
            "NOOIE_PACKAGE_NAME", "com.nooie.home"
        ),
        "language": os.environ.get("NOOIE_LANGUAGE", "en"),
        "app_version_code": os.environ.get(
            "NOOIE_APP_VERSION_CODE", "11"
        ),
        "country": os.environ.get("NOOIE_COUNTRY_CODE", "44"),
        "push_type": int(os.environ.get("NOOIE_PUSH_TYPE", "3")),
        "phone_model": os.environ.get("NOOIE_PHONE_MODEL", "iPad8,6"),
    }


async def register_user_client(
    http: aiohttp.ClientSession, config: Config
) -> None:
    """Run the normal post-login install registration used by Nooie."""
    async with http.post(
        f"{config.api_base}/user/put",
        headers=request_headers(config),
        json=client_registration(config),
    ) as response:
        payload = await response.json(content_type=None)
    if (
        response.status != 200
        or not isinstance(payload, dict)
        or payload.get("code") != 1000
    ):
        code = payload.get("code") if isinstance(payload, dict) else None
        message = payload.get("msg") if isinstance(payload, dict) else None
        raise RuntimeError(
            f"client registration failed: HTTP {response.status}, "
            f"code={code}, msg={message!r}"
        )


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
    body = login_request_body(
        username,
        password,
        phone_code,
        os.environ.get("NOOIE_COUNTRY_CODE", "44"),
        zone,
    )
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
        await register_user_client(http, config)
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
    servers = []
    for item in session.get("user_ices", []):
        url = item.get("iceurl")
        if url:
            servers.append(
                RTCIceServer(
                    urls=url,
                    username=item.get("username") or None,
                    credential=item.get("password") or None,
                )
            )
    return servers


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
        try:
            return cast(list[Frame], self.codec.decode(packet))
        except InvalidDataError:
            # Some cameras intermittently emit an incomplete AAC access unit.
            # Dropping that unit keeps aiortc's decoder worker alive for the
            # following valid RTP packets.
            return []


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


def enable_nooie_ice_credentials() -> None:
    """Match the credential sizes generated by Nooie's WebRTC build."""
    if getattr(aioice.ice.random_string, "_nooie_lengths", False):
        return
    original_random_string = aioice.ice.random_string

    def random_string(length: int) -> str:
        # aioice's default four-character ufrag matches all 24 captured
        # official offers. Nooie's build differs only in its 24-character
        # password (aioice normally requests 22).
        nooie_length = {22: 24}.get(length, length)
        return original_random_string(nooie_length)

    setattr(random_string, "_nooie_lengths", True)
    aioice.ice.random_string = random_string


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


def local_candidates(sdp: str) -> list[LocalIceCandidate]:
    """usable IPv4 candidates worth trickling, loopback and mDNS excluded."""
    chosen: list[LocalIceCandidate] = []
    ice_ufrag = sdp_value(sdp, "a=ice-ufrag:")
    sdp_mid = ""
    sdp_mline_index = -1
    for line in sdp.splitlines():
        if line.startswith("m="):
            sdp_mline_index += 1
            sdp_mid = str(sdp_mline_index)
            continue
        if line.startswith("a=mid:"):
            sdp_mid = line[len("a=mid:") :]
            continue
        if not line.startswith("a=candidate:"):
            continue
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
    # Nooie's offer is BUNDLE-only and its iOS client trickles the shared
    # transport once, against the first (video) media section.
    return [
        candidate
        for candidate in chosen
        if candidate.sdp_mline_index == 0
    ]


def compact_sdp_offer(sdp: str) -> str:
    """encode the reduced SDP dialect used by the Nooie iOS WebRTC build."""
    ice_ufrag = sdp_value(sdp, "a=ice-ufrag:")
    ice_pwd = sdp_value(sdp, "a=ice-pwd:")
    fingerprint = sdp_value(sdp, "a=fingerprint:")
    # Every preserved iOS offer uses a 19-digit WebRTC origin session ID.
    # aiortc uses a shorter timestamp-like value, so generate the native shape
    # independently; the compact offer is the only SDP representation sent.
    session_id = str(
        1_000_000_000_000_000_000
        + secrets.randbelow(9_000_000_000_000_000_000)
    )
    cname = base64.b64encode(secrets.token_bytes(12)).decode()
    video_ssrc = str(secrets.randbits(32))
    video_rtx_ssrc = str(secrets.randbits(32))
    audio_ssrc = str(secrets.randbits(32))

    common: dict[str, Any] = {
        "o": "trickle renomination",
        "I": " IP4 0.0.0.0",
        "tcc": 4,
        "p": ice_pwd,
        "is": 1,
        "isc": " WMS Lo",
        "ll": 14,
        "r": "9 IN IP4 0.0.0.0",
        "iO": f" {session_id} 2 IN IP4 127.0.0.1",
        "iT": "0 0",
        "s": "actpass",
        "iG": "0 1",
        "pp": 12,
        "u": ice_ufrag,
        "abs": 7,
        "ft": fingerprint,
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
            "sc": [video_ssrc, video_rtx_ssrc],
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


def compact_outbound_candidate(candidate: LocalIceCandidate) -> str:
    """Encode the numeric ICE candidate shape emitted by Nooie's SDK."""
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
    source_foundation = fields[0][len("candidate:") :]
    numeric_foundation = zlib.crc32(
        f"{source_foundation}:{kind}".encode()
    )
    output = [
        f"candidate:{numeric_foundation}",
        fields[1],
        fields[2].lower(),
        priorities[kind],
        fields[4],
        fields[5],
        "typ",
        kind,
    ]
    if kind in ("srflx", "relay"):
        output.extend(["raddr", "0.0.0.0", "rport", "0"])
    output.extend(
        [
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
    return " ".join(output)


def expand_compact_candidate(value: str) -> str:
    value = value.strip()
    if value.startswith("candidate:"):
        value = value[len("candidate:") :]
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
    algorithm, separator, digest = fingerprint.partition(" ")
    if separator:
        fingerprint = f"{algorithm} {digest.lstrip()}"
    elif fingerprint.startswith("sha-256"):
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
    config: Config,
    session: dict[str, Any],
    call: SignallingCall,
    sdp: str,
) -> dict[str, Any]:
    urls, usernames, passwords = device_ice_fields(session)
    envelope = {
        "method": "service.SdpOffer",
        "msg_id": call.next_message_id(call_scoped=True),
        "ver": "1.0",
        "time": int(time.time()),
        "origin": 1,
        "uuid": config.device_id,
        "device_model": config.model_id,
        "data": {
            "SessionId": session["session_id"],
            "call_id": call.call_id,
            "IceUrl": urls,
            "IceUsername": usernames,
            "IcePassword": passwords,
            "WebrtcSdp": sdp,
            "Action": 2,
            "TrickleICE": 0,
            "Timestamp": 0,
            "CodecMode": 1,
            "Quality": 1,
            "EnableSpeaker": False,
            "EnableMic": False,
            "Prepare": 0,
            "dtlsTimeOut": 2000,
            "onlyRelay": 0,
        },
    }
    return envelope


def signalling_switch(
    config: Config,
    session: dict[str, Any],
    call: SignallingCall,
) -> dict[str, Any]:
    return {
        "method": "service.Switch",
        "msg_id": call.next_message_id(),
        "ver": "1.0",
        "tme": int(time.time()),
        "origin": 1,
        "uuid": config.device_id,
        "device_model": config.model_id,
        "data": {
            "SessionId": session["session_id"],
            "call_id": call.call_id,
            "Action": 0,
        },
    }


def signalling_candidate(
    config: Config,
    session: dict[str, Any],
    call: SignallingCall,
    candidate: LocalIceCandidate,
) -> dict[str, Any]:
    return {
        "method": "service.IceCandidate",
        "msg_id": call.next_message_id(),
        "ver": "1.0",
        "time": int(time.time()),
        "origin": 1,
        "uuid": config.device_id,
        "device_model": config.model_id,
        "data": {
            "SessionId": session["session_id"],
            "call_id": call.call_id,
            "WebrtcCandidate": compact_outbound_candidate(candidate),
            "WebrtcSdpMLineIndex": candidate.sdp_mline_index,
            "WebrtcSdpMid": candidate.sdp_mid,
            "nsType": "",
            "type": "candidate",
        },
    }


def signalling_close(
    config: Config,
    session: dict[str, Any],
    call: SignallingCall,
) -> dict[str, Any]:
    return {
        "method": "service.Close",
        "msg_id": call.next_message_id(),
        "ver": "1.0",
        "time": int(time.time()),
        "origin": 1,
        "uuid": config.device_id,
        "device_model": config.model_id,
        "data": {
            "SessionId": session["session_id"],
            "call_id": call.call_id,
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
    # Device trickle may arrive either space-separated or in the older
    # space-free representation; ordinary answers use a "candidate" field.
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


# container muxers for the non-file sinks vlc can open. anything with a
# scheme goes out as mpeg-ts, which vlc plays back live; "-" means stdout.
STREAM_MUXERS = {
    "pipe": "mpegts",
    "udp": "mpegts",
    "tcp": "mpegts",
    "srt": "mpegts",
    "http": "mpegts",
    "https": "mpegts",
    "rtp": "rtp",
    "rtsp": "rtsp",
}


def recorder_target(output: str) -> tuple[str, str | None]:
    """resolve --output into a pyav target and container format."""
    target = "pipe:1" if output == "-" else output
    head = target.split("://", 1)[0] if "://" in target else target
    return target, STREAM_MUXERS.get(head.split(":", 1)[0])


async def receive(
    config: Config, output: str, duration: float
) -> None:
    enable_rsa_dtls()
    enable_nooie_ice_credentials()
    # publish our nat mapping on the p2p network so the camera can reach us.
    # Keep the registration object and its UDP socket alive for the call.
    print("registering on the p2p network", flush=True)
    _registration = await asyncio.to_thread(apeman.register, config.uid)
    print("p2p registration complete", flush=True)
    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(
        timeout=timeout,
        skip_auto_headers={
            "Accept",
            "Accept-Encoding",
            "User-Agent",
        },
    ) as http:
        ws_headers = {
            "uid": config.uid,
            "appid": config.app_id,
            "api_token": config.api_token,
            "phone_code": config.phone_code,
            "Origin": websocket_origin(config.ws_url),
        }
        print("connecting to Nooie signalling WebSocket", flush=True)
        async with http.ws_connect(
            config.ws_url, headers=ws_headers, heartbeat=20
        ) as websocket:
            call = SignallingCall()
            print("creating Nooie WebRTC session", flush=True)
            session = await create_session(http, config)
            peer = RTCPeerConnection(
                RTCConfiguration(
                    iceServers=ice_servers(session),
                    bundlePolicy=RTCBundlePolicy.MAX_BUNDLE,
                )
            )
            target, muxer = recorder_target(output)
            recorder = MediaRecorder(target, format=muxer)
            recorder_start: asyncio.Task[None] | None = None
            connected = asyncio.Event()
            # ctrl-c has to unwind the loop rather than kill it, or the
            # container never gets flushed and closed.
            interrupted = asyncio.Event()
            asyncio.get_running_loop().add_signal_handler(
                SIGINT, interrupted.set
            )

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

            try:
                force_h264(peer)
                offer = await peer.createOffer()
                await peer.setLocalDescription(offer)
                if peer.localDescription is None:
                    raise RuntimeError(
                        "aiortc did not produce a local description"
                    )
                frame = signalling_offer(
                    config,
                    session,
                    call,
                    compact_sdp_offer(peer.localDescription.sdp),
                )
                await websocket.send_json(
                    frame, dumps=websocket_json_dumps
                )
                for local_candidate in local_candidates(
                    peer.localDescription.sdp
                ):
                    await websocket.send_json(
                        signalling_candidate(
                            config,
                            session,
                            call,
                            local_candidate,
                        ),
                        dumps=websocket_json_dumps,
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
                        signal = matching_signal(
                            value, call.call_id, session["session_id"]
                        )
                        if signal is None:
                            continue
                        data = signal["data"]
                        if "SdpAnswer" in signal["method"]:
                            ret = int(data.get("Ret", 0))
                            if ret != 0:
                                raise RuntimeError(
                                    f"camera rejected the call with Ret={ret}"
                                )
                            answer_sdp = data.get("WebrtcSdp")
                            if answer_sdp:
                                answer_sdp = compact_sdp_answer(
                                    str(answer_sdp)
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
                    signalling_switch(config, session, call),
                    dumps=websocket_json_dumps,
                )
                print("live stream requested", flush=True)
                try:
                    async with asyncio.timeout(2):
                        await websocket.receive()
                except TimeoutError:
                    pass
                await activate_video(peer)
                print("video receiver activated", flush=True)
                print(
                    f"{'streaming' if muxer else 'recording'} "
                    + (
                        f"{duration:g} seconds"
                        if duration > 0
                        else "until interrupted"
                    )
                    + f" to {target}",
                    flush=True,
                )
                recording_deadline = time.monotonic() + duration
                while not interrupted.is_set() and (
                    duration <= 0 or time.monotonic() < recording_deadline
                ):
                    remaining = recording_deadline - time.monotonic()
                    try:
                        async with asyncio.timeout(
                            min(1, remaining) if duration > 0 else 1.0
                        ):
                            status_message = await websocket.receive()
                    except TimeoutError:
                        continue
                    if status_message.type == aiohttp.WSMsgType.TEXT:
                        try:
                            value = json.loads(status_message.data)
                        except json.JSONDecodeError:
                            continue
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
                        f"{report.kind}={report.packetsReceived} packets"
                        + (
                            f"/{report.bytesReceived} bytes"
                            if hasattr(report, "bytesReceived")
                            else ""
                        )
                        for report in inbound
                    ),
                    flush=True,
                )
            finally:
                # always release the session so the camera's small P2P
                # connection pool does not fill with half-open calls.
                if not websocket.closed:
                    try:
                        await websocket.send_json(
                            signalling_close(config, session, call),
                            dumps=websocket_json_dumps,
                        )
                    except (aiohttp.ClientError, ConnectionError):
                        pass
                if recorder_start is not None:
                    await recorder_start
                await recorder.stop()
                await peer.close()


async def run(output: str, duration: float) -> None:
    config = await login_config()
    thing_app = thing_app_from_environment()
    thing_device_id = load_or_create_device_id()
    _, password = login_environment()
    country_code = os.environ.get("NOOIE_COUNTRY_CODE", "44")

    print("logging into Thing with an independent device identity", flush=True)
    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(timeout=timeout) as http:
        thing_client = ThingClient(thing_app, thing_device_id)
        thing_session = await thing_client.login_by_uid(
            http,
            config.uid,
            password,
            country_code,
        )
        print("Thing UID login succeeded", flush=True)

        # The SDK opens MQTT immediately after login, then performs its final
        # home bootstrap on the still-live HTTPS session.
        async with mqtt_presence(
            thing_app,
            thing_session,
            thing_device_id,
        ):
            home_spaces = await thing_client.home_spaces(
                http, thing_session
            )
            home_device_lists = []
            for home in home_spaces:
                raw_home_id = home.get("gid", home.get("groupId"))
                try:
                    home_id = int(raw_home_id)
                except (TypeError, ValueError):
                    continue
                home_device_lists.append(
                    await thing_client.home_devices(
                        http, thing_session, home_id
                    )
                )
            device_count = sum(
                len(items)
                for items in home_device_lists
                if isinstance(items, list)
            )
            print(
                f"Thing home bootstrap loaded {len(home_spaces)} "
                f"home{'s' if len(home_spaces) != 1 else ''} and "
                f"{device_count} device entries",
                flush=True,
            )
            await receive(config, output, duration)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="receive live A/V from your Nooie camera over its WebRTC path"
    )
    parser.add_argument(
        "username",
        nargs="?",
        help="Nooie account username/email (password is prompted)",
    )
    parser.add_argument(
        "--output",
        default="nooie.mp4",
        help=(
            "recording path, or a live mpeg-ts sink vlc can open: "
            "udp://127.0.0.1:5004, tcp://127.0.0.1:5004?listen, "
            "or - for stdout"
        ),
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=30,
        help="seconds to record; 0 runs until ctrl-c",
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
    if args.username:
        os.environ["NOOIE_USERNAME"] = args.username
        if not os.environ.get("NOOIE_PASSWORD"):
            os.environ["NOOIE_PASSWORD"] = getpass("Nooie password: ")
    if args.check_config:
        login_environment()
        app_credentials()
        thing_app_from_environment()
        configured_thing_id = os.environ.get("NOOIE_THING_DEVICE_ID", "")
        if configured_thing_id:
            normalize_device_id(configured_thing_id)
        print("configuration is complete")
        return
    target, muxer = recorder_target(args.output)
    if muxer is None and Path(target).exists():
        raise SystemExit(f"refusing to overwrite {target}")
    if target.startswith("pipe:1"):
        # the muxer owns fd 1; keep our chatter off it.
        sys.stdout = sys.stderr
    asyncio.run(run(args.output, args.duration))


if __name__ == "__main__":
    main()
