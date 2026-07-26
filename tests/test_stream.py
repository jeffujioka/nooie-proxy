import fractions
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from nooie_proxy.stream import TICK, Timed, aligned, container

VIDEO = fractions.Fraction(1, 90000)
AUDIO = fractions.Fraction(1, 48000)


class Track:
    """a track handing over frames dated by the camera."""

    def __init__(
        self, kind: str, time_base: fractions.Fraction, stamps: list[int]
    ) -> None:
        self.kind = kind
        self.frames = [
            SimpleNamespace(pts=stamp, time_base=time_base) for stamp in stamps
        ]

    async def recv(self) -> SimpleNamespace:
        return self.frames.pop(0)


class ContainerTests(unittest.TestCase):
    def test_pipes_and_files_get_fragmented_mp4(self) -> None:
        for target in ("pipe:1", "/tmp/a.mp4", "clip.mkv"):
            muxer, options = container(target)
            self.assertEqual(muxer, "mp4")
            self.assertIn("movflags", options)

    def test_network_sinks_get_joinable_mpegts(self) -> None:
        for target in (
            "udp://127.0.0.1:5004",
            "tcp://127.0.0.1:5004?listen",
            "srt://host:9000",
            "http://host/live",
        ):
            self.assertEqual(container(target), ("mpegts", {}))


class AlignedTests(unittest.TestCase):
    def test_udp_datagrams_hold_whole_transport_packets(self) -> None:
        self.assertEqual(
            aligned("udp://127.0.0.1:5004"),
            "udp://127.0.0.1:5004?pkt_size=1316",
        )
        self.assertEqual(
            aligned("udp://127.0.0.1:5004?ttl=1"),
            "udp://127.0.0.1:5004?ttl=1&pkt_size=1316",
        )

    def test_other_sinks_and_a_chosen_size_are_left_alone(self) -> None:
        for target in (
            "pipe:1",
            "srt://host:9000",
            "udp://127.0.0.1:5004?pkt_size=188",
        ):
            self.assertEqual(aligned(target), target)


class TimedTests(unittest.IsolatedAsyncioTestCase):
    async def stamps(self, track: Track, wall: list[float]) -> list[int]:
        timed = Timed(track, 0.0)  # type: ignore[arg-type]
        with patch("nooie_proxy.stream.time.monotonic", side_effect=wall):
            return [(await timed.recv()).pts for _ in wall]

    async def test_video_is_dated_by_arrival_not_by_the_camera(self) -> None:
        # the camera's clock gains: 100ms of timestamps every 80ms.
        stamps = await self.stamps(
            Track("video", VIDEO, [index * 9000 for index in range(5)]),
            [index * 0.08 for index in range(5)],
        )

        self.assertEqual(stamps, [0, 7200, 14400, 21600, 28800])

    async def test_audio_keeps_its_cadence_from_one_origin(self) -> None:
        stamps = await self.stamps(
            Track("audio", AUDIO, [70000 + index * 960 for index in range(4)]),
            [1.0 + index * 0.02 for index in range(4)],
        )

        self.assertEqual(stamps[0], 48000)
        steps = [b - a for a, b in zip(stamps, stamps[1:])]
        self.assertEqual(steps, [960] * 3)

    async def test_frames_arriving_within_a_tick_stay_distinct(self) -> None:
        stamps = await self.stamps(
            Track("video", VIDEO, [0, 0, 0]), [1.0, 1.0, 1.0]
        )

        step = TICK["video"]
        self.assertEqual(stamps, [90000, 90000 + step, 90000 + 2 * step])


if __name__ == "__main__":
    unittest.main()
