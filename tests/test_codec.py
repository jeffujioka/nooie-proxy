# tests/test_codec.py
from nooie_proxy import codec


def test_pt_zero_means_h265():
    assert codec.select_codec(0) == "h265"


def test_dynamic_pt_means_h264():
    assert codec.select_codec(126) == "h264"
    assert codec.select_codec(96) == "h264"


def test_arbitrary_and_missing_pt_default_to_h264():
    assert codec.select_codec(42) == "h264"
    assert codec.select_codec(None) == "h264"


def test_override_wins():
    assert codec.select_codec(0, "h264") == "h264"
    assert codec.select_codec(126, "h265") == "h265"


def test_invalid_override_falls_back_to_heuristic():
    assert codec.select_codec(0, "hevc") == "h265"
    assert codec.select_codec(126, "") == "h264"


def test_session_state_roundtrip():
    assert codec.video_codec() == "h264"  # default
    codec.set_video_codec("h265")
    assert codec.video_codec() == "h265"
    codec.set_video_codec("h264")  # restore para outros testes
