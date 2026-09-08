"""bug 1 regression and the aiortc canary.

the camera announces h.264-labelled video on the static payload type 0;
stock aiortc only adopts a remote payload type from the dynamic range
(96-127), so the receiver registers pt 126 and the rtp router drops every
video packet. the patched find_common_codecs adopts the remote type
unconditionally.
"""
import inspect

import aiortc
import aiortc.rtcpeerconnection as rpc
from aiortc.rtcrtpparameters import RTCRtpCodecParameters

from nooie_proxy import rtc


def h264(pt: int) -> RTCRtpCodecParameters:
    return RTCRtpCodecParameters(
        mimeType="video/H264", clockRate=90000, payloadType=pt
    )


def test_bug1_regression_static_pt_is_adopted():
    rtc.patch()
    common = rpc.find_common_codecs([h264(126)], [h264(0)])
    assert [c.payloadType for c in common] == [0]


def test_dynamic_pt_still_adopted():
    rtc.patch()
    common = rpc.find_common_codecs([h264(126)], [h264(102)])
    assert [c.payloadType for c in common] == [102]


def test_patch_is_idempotent():
    rtc.patch()
    first = rpc.find_common_codecs
    rtc.patch()
    assert rpc.find_common_codecs is first


def test_aiortc_canary():
    """every monkeypatch target must exist as pinned; a bump that moves one
    fails here instead of at 3 a.m. against the camera."""
    import aiortc.codecs
    import aiortc.rtcrtpreceiver
    import aioice.ice
    from aiortc.rtcdtlstransport import SSL, RTCCertificate

    assert aiortc.__version__.startswith("1.15.")
    # _adopt_remote_payload_types
    assert list(inspect.signature(rpc.find_common_codecs).parameters) == [
        "local_codecs",
        "remote_codecs",
    ]
    assert callable(rpc.is_codec_compatible) and callable(rpc.is_rtx)
    # _enable_h265_depacketization (task 5)
    assert callable(aiortc.codecs.depayload)
    assert callable(aiortc.rtcrtpreceiver.depayload)
    assert callable(aiortc.codecs.get_decoder)
    # upstream patches (rsa dtls, ice credentials) keep working too
    assert hasattr(RTCCertificate, "generateCertificate")
    assert hasattr(SSL, "Connection")
    assert callable(aioice.ice.random_string)
