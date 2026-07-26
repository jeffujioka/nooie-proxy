import unittest

from nooie_tui.client import recorder_target


class RecorderTargetTest(unittest.TestCase):
    def test_paths_keep_the_autodetected_muxer(self) -> None:
        for path in ("nooie.mp4", "clips/nooie.mkv", "/tmp/nooie.mp4"):
            self.assertEqual(recorder_target(path), (path, None))

    def test_stdout_and_urls_become_live_containers(self) -> None:
        self.assertEqual(recorder_target("-"), ("pipe:1", "mpegts"))
        self.assertEqual(
            recorder_target("udp://127.0.0.1:5004"),
            ("udp://127.0.0.1:5004", "mpegts"),
        )
        self.assertEqual(
            recorder_target("rtsp://127.0.0.1:8554/nooie"),
            ("rtsp://127.0.0.1:8554/nooie", "rtsp"),
        )


if __name__ == "__main__":
    unittest.main()
