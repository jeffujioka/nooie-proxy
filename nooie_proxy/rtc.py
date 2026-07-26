"""the adjustments aiortc needs before nooie's cameras will talk to it.

nooie's build predates several aiortc defaults: it offers aac audio aiortc has
no codec for, only accepts rsa dtls certificates at a 1200-byte mtu, and its
ice password is 24 characters rather than 22.
"""

import fractions
import os
import re
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import aioice.ice
import aiortc.codecs
import aiortc.rtcrtpreceiver
from aiortc import RTCPeerConnection, RTCRtpSender
from aiortc.codecs.base import Decoder
from aiortc.jitterbuffer import JitterFrame
from aiortc.rtcdtlstransport import SSL, RTCCertificate
from aiortc.rtcrtpparameters import (
    RTCRtcpFeedback,
    RTCRtpCodecParameters,
    RTCRtpHeaderExtensionParameters,
)
from av import CodecContext, InvalidDataError
from av.frame import Frame
from av.packet import Packet
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

TRANSPORT_CC = RTCRtpHeaderExtensionParameters(
    id=4,
    uri="http://www.ietf.org/id/"
    "draft-holmer-rmcat-transport-wide-cc-extensions-01",
)
AAC = RTCRtpCodecParameters(
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
)


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
            data = data[4:]  # rfc 3640 au header
        packet = Packet(data)
        packet.pts = encoded_frame.timestamp
        packet.time_base = self.time_base
        try:
            return cast(list[Frame], self.codec.decode(packet))
        except InvalidDataError:
            # some cameras intermittently emit an incomplete access unit;
            # dropping it keeps aiortc's decoder worker alive for the rest.
            return []


def _enable_aac() -> None:
    codecs = aiortc.codecs.CODECS["audio"]
    if not any(codec.mimeType.lower() == "audio/aac" for codec in codecs):
        aiortc.codecs.CODECS["audio"] = [
            AAC,
            *(codec for codec in codecs if codec.payloadType != 96),
        ]
    original = aiortc.codecs.get_decoder

    def get_decoder(codec: RTCRtpCodecParameters) -> Decoder:
        if codec.mimeType.lower() == "audio/aac":
            return AacDecoder(codec)
        return original(codec)

    aiortc.codecs.get_decoder = get_decoder
    aiortc.rtcrtpreceiver.get_decoder = get_decoder


def _enable_rsa_dtls() -> None:
    def generate(cls: type[RTCCertificate]) -> RTCCertificate:
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        name = x509.Name(
            [x509.NameAttribute(x509.NameOID.COMMON_NAME, "WebRTC")]
        )
        now = datetime.now(UTC)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(int.from_bytes(os.urandom(8), "big") | (1 << 63))
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=30))
            .sign(key, hashes.SHA256())
        )
        return cls(key=key, cert=certificate)

    def ssl_context(
        certificate: RTCCertificate, srtp_profiles: list[Any]
    ) -> SSL.Context:
        context = SSL.Context(SSL.DTLS_METHOD)
        context.set_options(SSL.OP_NO_QUERY_MTU)
        context.set_verify(
            SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT, lambda *_: True
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
    RTCCertificate._create_ssl_context = ssl_context
    if getattr(SSL.Connection, "_nooie_mtu", False):
        return
    SSL.Connection._nooie_mtu = True
    original_init = SSL.Connection.__init__
    original_accept = SSL.Connection.set_accept_state

    def connection_init(connection: SSL.Connection, *args: Any) -> None:
        original_init(connection, *args)
        connection.set_ciphertext_mtu(1200)
        SSL._lib.SSL_set_mtu(connection._ssl, 1200)

    def set_accept_state(connection: SSL.Connection) -> None:
        original_accept(connection)
        SSL._lib.SSL_set_mtu(connection._ssl, 1200)

    SSL.Connection.__init__ = connection_init
    SSL.Connection.set_accept_state = set_accept_state


def _enable_nooie_ice_credentials() -> None:
    """match the credential sizes generated by nooie's webrtc build."""
    if getattr(aioice.ice.random_string, "_nooie_lengths", False):
        return
    original = aioice.ice.random_string

    def random_string(length: int) -> str:
        # aioice's four-character ufrag already matches every captured
        # official offer; only the password length differs.
        return original(24 if length == 22 else length)

    random_string._nooie_lengths = True
    aioice.ice.random_string = random_string


def patch() -> None:
    _enable_aac()
    _enable_rsa_dtls()
    _enable_nooie_ice_credentials()


def receive_only(peer: RTCPeerConnection) -> None:
    """offer exactly the one h264 and one aac receiver the camera expects."""
    for kind in ("audio", "video"):
        extensions = aiortc.codecs.HEADER_EXTENSIONS[kind]
        if not any(item.id == TRANSPORT_CC.id for item in extensions):
            extensions.append(TRANSPORT_CC)
    source = next(
        codec
        for codec in aiortc.codecs.CODECS["video"]
        if codec.mimeType.lower() == "video/h264"
        and codec.parameters.get("profile-level-id") == "42e01f"
    )
    aiortc.codecs.CODECS["video"] = [
        RTCRtpCodecParameters(
            mimeType=source.mimeType,
            clockRate=source.clockRate,
            payloadType=126,
            rtcpFeedback=[
                *source.rtcpFeedback,
                RTCRtcpFeedback(type="transport-cc"),
            ],
            parameters=source.parameters,
        )
    ]
    for kind, mime in (("video", "video/h264"), ("audio", "audio/aac")):
        transceiver = peer.addTransceiver(kind, direction="recvonly")
        codecs = [
            codec
            for codec in RTCRtpSender.getCapabilities(kind).codecs
            if codec.mimeType.lower() == mime
        ]
        if not codecs:
            raise RuntimeError(f"this aiortc build has no {mime} codec")
        transceiver.setCodecPreferences(codecs)
