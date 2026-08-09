import fractions
import unittest

from aiortc.jitterbuffer import JitterFrame
from aiortc.rtcrtpparameters import RTCRtpCodecParameters

from nooie_proxy.rtc import AAC, Verbatim, opens_a_group

H264 = RTCRtpCodecParameters(
    mimeType="video/H264", clockRate=90000, payloadType=126
)


def unit(*nals: bytes) -> bytes:
    return b"".join(b"\x00\x00\x00\x01" + nal for nal in nals)


class GroupTests(unittest.TestCase):
    def test_parameter_sets_and_idr_open_a_group(self) -> None:
        self.assertTrue(opens_a_group(unit(b"\x67\x42\xe0\x1f")))  # sps
        self.assertTrue(opens_a_group(unit(b"\x65\x88\x84")))  # idr
        self.assertTrue(opens_a_group(unit(b"\x67\x42", b"\x65\x88")))

    def test_a_predicted_picture_does_not(self) -> None:
        self.assertFalse(opens_a_group(unit(b"\x41\x9a\x00")))
        self.assertFalse(opens_a_group(unit(b"\x06\x05\x01")))  # sei alone
        self.assertFalse(opens_a_group(b""))


class VerbatimTests(unittest.TestCase):
    def test_video_is_passed_on_whole_and_dated_in_its_clock(self) -> None:
        data = unit(b"\x65\x88\x84")
        (packet,) = Verbatim(H264).decode(JitterFrame(data=data, timestamp=90))

        self.assertEqual(bytes(packet), data)
        self.assertEqual(packet.pts, 90)
        self.assertEqual(packet.dts, 90)
        self.assertEqual(packet.time_base, fractions.Fraction(1, 90000))
        self.assertTrue(packet.is_keyframe)

    def test_audio_sheds_the_rfc_3640_header(self) -> None:
        frame = JitterFrame(data=b"\x00\x10\x0a\x18payload", timestamp=16)
        (packet,) = Verbatim(AAC).decode(frame)

        self.assertEqual(bytes(packet), b"payload")
        self.assertEqual(packet.time_base, fractions.Fraction(1, 16000))
        # every access unit is a point an aac decoder may start from.
        self.assertTrue(packet.is_keyframe)

    def test_the_camera_s_empty_access_units_are_dropped(self) -> None:
        padding = JitterFrame(data=b"\x00\x10\x00\x50" + bytes(10), timestamp=1)

        self.assertEqual(Verbatim(AAC).decode(padding), [])

    def test_audio_without_a_header_is_left_alone(self) -> None:
        frame = JitterFrame(data=b"\xff\xf1raw", timestamp=16)

        self.assertEqual(bytes(Verbatim(AAC).decode(frame)[0]), b"\xff\xf1raw")


if __name__ == "__main__":
    unittest.main()
