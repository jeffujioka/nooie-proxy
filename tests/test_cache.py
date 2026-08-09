import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from nooie_proxy import cache, cloud


class CacheTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp())
        patcher = patch("nooie_proxy.cache.state_dir", return_value=self.root)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_nothing_is_held_before_anything_is_saved(self) -> None:
        self.assertEqual(cache.load("nooie"), {})
        self.assertIsNone(cloud.stored())

    def test_a_saved_entry_reads_back(self) -> None:
        cache.save("nooie", {"api_token": "t", "uid": "u", "request": "r"})

        self.assertEqual(cache.load("nooie")["uid"], "u")

    def test_the_file_is_readable_only_by_its_owner(self) -> None:
        cache.save("nooie", {"api_token": "t"})

        self.assertEqual(cache.path().stat().st_mode & 0o777, 0o600)

    def test_a_damaged_file_is_no_session_rather_than_an_error(self) -> None:
        cache.path().write_text("{not json")

        self.assertEqual(cache.load("nooie"), {})

    def test_a_half_written_session_is_not_used(self) -> None:
        cache.save("nooie", {"api_token": "t", "uid": "u"})

        self.assertIsNone(cloud.stored())

    def test_a_forgotten_session_is_gone(self) -> None:
        cache.save("nooie", {"api_token": "t", "uid": "u", "request": "r"})

        cache.forget("nooie")

        self.assertEqual(cache.load("nooie"), {})


if __name__ == "__main__":
    unittest.main()
