from pathlib import Path

import av

from nooie_proxy import codec, sdp
from nooie_proxy.stream import Ending, Remux

ANSWER = "00\r\n" + Path("tests/fixtures/compact_answer.json").read_text().strip()


def test_answer_video_pt_reads_the_compact_answer():
    assert sdp.answer_video_pt(ANSWER) == 0


def test_answer_video_pt_none_for_plain_sdp():
    assert sdp.answer_video_pt("v=0\r\n...") is None
    assert sdp.answer_video_pt("00\r\n{not json") is None


def test_remux_declares_hevc_for_h265(tmp_path):
    codec.set_video_codec("h265")
    remux = Remux(str(tmp_path / "out.ts"), Ending())

    class Track:
        kind = "video"

    remux.add(Track())
    assert remux._video_codec_name == "hevc"
    codec.set_video_codec("h264")
    remux.container.close()


def test_remux_still_declares_h264_by_default(tmp_path):
    codec.set_video_codec("h264")
    remux = Remux(str(tmp_path / "out.ts"), Ending())

    class Track:
        kind = "video"

    remux.add(Track())
    assert remux._video_codec_name == "h264"
    remux.container.close()
