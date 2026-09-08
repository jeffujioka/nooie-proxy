"""the adjustments aiortc needs before nooie's cameras will talk to it.

nooie's build predates several aiortc defaults: it offers aac audio aiortc has
no codec for, only accepts rsa dtls certificates at a 1200-byte mtu, and its
ice password is 24 characters rather than 22.
"""

import copy
import fractions
import os
from datetime import UTC, datetime, timedelta
from typing import Any

import aioice.ice
import aiortc.codecs
import aiortc.rtcpeerconnection
import aiortc.rtcrtpreceiver

from . import codec as session_codec
from . import h265
from aiortc import RTCPeerConnection, RTCRtpSender
from aiortc.codecs.base import Decoder
from aiortc.jitterbuffer import JitterFrame
from aiortc.rtcdtlstransport import SSL, RTCCertificate
from aiortc.rtcrtpparameters import (
    RTCRtcpFeedback,
    RTCRtpCodecParameters,
    RTCRtpHeaderExtensionParameters,
)
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


def opens_a_group(access_unit: bytes) -> bool:
    """true when the unit carries an idr picture or the parameter sets.

    a consumer joining mid-stream can decode nothing until one arrives, so
    the muxer is told which packets a group of pictures may start on.
    """
    return any(
        nal and nal[0] & 0x1F in (5, 7)
        for nal in access_unit.split(b"\x00\x00\x01")
    )


class Verbatim(Decoder):
    """hand an access unit on as a packet, to be muxed without transcoding.

    aiortc decodes only so that it can re-encode. the camera already sends
    the h264 and aac a consumer wants, so the work left here is to shed
    rtp's own framing and date the packet in its clock.
    """

    def __init__(self, codec: RTCRtpCodecParameters) -> None:
        self.audio = codec.mimeType.lower().startswith("audio/")
        self.time_base = fractions.Fraction(1, codec.clockRate)

    def decode(self, encoded_frame: JitterFrame) -> list[Any]:
        data = encoded_frame.data
        if self.audio:
            if len(data) > 4 and data[:2] == b"\x00\x10":
                data = data[4:]  # rfc 3640 au header
            if not any(data):
                # the camera pads its audio with empty access units. they
                # carry no frame, and a player handed one says so loudly.
                return []
        packet = Packet(len(data))
        packet.update(data)
        packet.pts = packet.dts = encoded_frame.timestamp
        packet.time_base = self.time_base
        opener = (
            h265.opens_a_group
            if session_codec.video_codec() == "h265"
            else opens_a_group
        )
        packet.is_keyframe = self.audio or opener(data)
        return [packet]


def _enable_aac() -> None:
    codecs = aiortc.codecs.CODECS["audio"]
    if not any(codec.mimeType.lower() == "audio/aac" for codec in codecs):
        aiortc.codecs.CODECS["audio"] = [
            AAC,
            *(codec for codec in codecs if codec.payloadType != 96),
        ]


def _pass_media_through() -> None:
    """mux what the camera sends rather than decode it in order to re-encode.

    the call is negotiated down to one h264 and one aac stream, so every
    decoder aiortc asks for is one this proxy would rather not run.
    """

    def get_decoder(codec: RTCRtpCodecParameters) -> Decoder:
        return Verbatim(codec)

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


def _enable_h265_depacketization() -> None:
    """route video payloads through rfc 7798 when the camera sends h.265.

    the answer still says h264 (nooie's dialect names no codec; see
    codec.select_codec), so the depacketizer is chosen by the session codec
    rather than by the negotiated mime type. audio and genuine h.264 video
    pass through stock aiortc untouched.
    """
    original = aiortc.codecs.depayload
    if getattr(original, "_nooie_h265", False):
        return

    def depayload(params, payload):  # type: ignore[no-untyped-def]
        if (
            params.mimeType.lower() == "video/h264"
            and session_codec.video_codec() == "h265"
        ):
            return h265.h265_depayload(payload)
        return original(params, payload)

    depayload._nooie_h265 = True  # type: ignore[attr-defined]
    aiortc.codecs.depayload = depayload
    # rtcrtpreceiver imported the symbol at module load; patch that copy too.
    aiortc.rtcrtpreceiver.depayload = depayload


def _adopt_remote_payload_types() -> None:
    """nooie's h.265 cameras announce video on the static payload type 0.

    stock find_common_codecs only adopts a remote payload type from the
    dynamic range, so the receiver would register pt 126 while the camera
    sends pt 0, and the rtp router would drop every video packet. this peer
    only ever speaks to the camera, so adopt the remote type as announced.
    """
    module = aiortc.rtcpeerconnection
    if getattr(module.find_common_codecs, "_nooie_adopts_static", False):
        return
    is_codec_compatible = module.is_codec_compatible
    is_rtx = module.is_rtx

    def find_common_codecs(local_codecs, remote_codecs):  # type: ignore[no-untyped-def]
        common = []
        common_base = {}
        for c in remote_codecs:
            if is_rtx(c):
                apt = c.parameters.get("apt")
                if isinstance(apt, int) and apt in common_base:
                    base = common_base[apt]
                    if c.clockRate == base.clockRate:
                        common.append(copy.deepcopy(c))
                continue
            for codec in local_codecs:
                if is_codec_compatible(codec, c):
                    codec = copy.deepcopy(codec)
                    codec.payloadType = c.payloadType
                    codec.rtcpFeedback = list(
                        filter(lambda x: x in c.rtcpFeedback, codec.rtcpFeedback)
                    )
                    common.append(codec)
                    common_base[codec.payloadType] = codec
                    break
        return common

    find_common_codecs._nooie_adopts_static = True  # type: ignore[attr-defined]
    module.find_common_codecs = find_common_codecs


def patch() -> None:
    _enable_aac()
    _pass_media_through()
    _enable_rsa_dtls()
    _enable_nooie_ice_credentials()
    _adopt_remote_payload_types()
    _enable_h265_depacketization()


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
