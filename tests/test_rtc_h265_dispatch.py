import aiortc.codecs
import aiortc.rtcrtpreceiver
from aiortc.rtcrtpparameters import RTCRtpCodecParameters

from nooie_proxy import codec, rtc

VIDEO = RTCRtpCodecParameters(mimeType="video/H264", clockRate=90000, payloadType=0)
AUDIO = rtc.AAC
# fu h.265 (start) carregando um idr — inerte para o parser h.264
H265_FU = bytes([49 << 1, 0x01, 0x80 | 19]) + b"\x99" * 20
# single nal h.264 (sps 0x67)
H264_NAL = b"\x67\x42\x00\x1f\xda"


def setup_function(_):
    rtc.patch()
    codec.set_video_codec("h264")


def test_h264_path_is_byte_identical_to_stock():
    stock = aiortc.codecs.h264.H264PayloadDescriptor.parse(H264_NAL)[1]
    assert aiortc.codecs.depayload(VIDEO, H264_NAL) == stock


def test_h265_video_is_depacketized_per_rfc7798():
    codec.set_video_codec("h265")
    out = aiortc.codecs.depayload(VIDEO, H265_FU)
    assert out.startswith(b"\x00\x00\x01" + bytes([0x26, 0x01]))


def test_audio_is_untouched_either_way():
    codec.set_video_codec("h265")
    payload = b"\x00\x10\x01\x00" + b"\x55" * 8
    assert aiortc.codecs.depayload(AUDIO, payload) == payload


def test_receiver_module_reference_is_also_patched():
    assert aiortc.rtcrtpreceiver.depayload is aiortc.codecs.depayload


def test_verbatim_keyframe_dispatch():
    verbatim = rtc.Verbatim(VIDEO)

    class Frame:
        data = b"\x00\x00\x01" + bytes([0x26, 0x01]) + b"\xbb" * 8  # idr h265
        timestamp = 0

    codec.set_video_codec("h265")
    (packet,) = verbatim.decode(Frame())
    assert packet.is_keyframe is True
    codec.set_video_codec("h264")
    (packet,) = verbatim.decode(Frame())
    # como h.264, 0x26 & 0x1f = 6 (sei) -> nao e keyframe
    assert packet.is_keyframe is False
