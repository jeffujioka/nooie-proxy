import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from nooie_proxy.env import load_dotenv

# a credential is far likelier to contain punctuation than the file is to want
# shell semantics, so every one of these must survive verbatim. mangling one
# only shows up later as an unexplained login failure.
LITERAL = {
    "PLAIN": "s3cret",
    "DOLLAR": "pa$$word",
    "HASH": "pa#ss",
    "APOSTROPHE": "pa'ss'x",
    "SPACE": "pa ss",
    "BANG": "pa!ss",
    "BACKSLASH": "pa\\ss",
    "EQUALS": "a=b=c",
    "BRACES": "${HOME}",
}


class DotenvTests(unittest.TestCase):
    def load(self, text: str) -> dict[str, str]:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / ".env"
            path.write_text(text)
            with patch.dict(os.environ, {}, clear=True):
                load_dotenv(path)
                return dict(os.environ)

    def test_values_are_taken_literally(self) -> None:
        loaded = self.load(
            "".join(f"{key}={value}\n" for key, value in LITERAL.items())
        )

        for key, value in LITERAL.items():
            self.assertEqual(loaded[key], value, f"{key} was mangled")

    def test_quotes_are_stripped_and_preserve_surrounding_space(self) -> None:
        loaded = self.load('A="pa#ss"\nB=" pa "\nC=\'x y\'\n')

        self.assertEqual(loaded["A"], "pa#ss")
        self.assertEqual(loaded["B"], " pa ")
        self.assertEqual(loaded["C"], "x y")

    def test_trailing_comments_and_export_are_understood(self) -> None:
        loaded = self.load(
            "# a whole-line comment\n\nexport A=44  # the region\nB=\n"
        )

        self.assertEqual(loaded["A"], "44")
        self.assertEqual(loaded["B"], "")
        self.assertNotIn("#", loaded["A"])

    def test_the_environment_wins_over_the_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / ".env"
            path.write_text("A=from-file\n")
            with patch.dict(os.environ, {"A": "from-environment"}, clear=True):
                load_dotenv(path)
                self.assertEqual(os.environ["A"], "from-environment")

    def test_a_malformed_line_is_refused(self) -> None:
        with self.assertRaises(SystemExit):
            self.load("NOT A VALID LINE\n")


if __name__ == "__main__":
    unittest.main()
