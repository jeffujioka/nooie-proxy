import collections
from pathlib import Path

from nooie_proxy import codec
from nooie_proxy.diagnose import Observer, build_report

ANSWER = "00\r\n" + Path("tests/fixtures/compact_answer.json").read_text().strip()


def observer_with_data() -> Observer:
    observer = Observer()
    observer.answer = ANSWER
    observer.tracks["video"] = {"packets": 100, "bytes": 750_000, "first": 12.0}
    observer.tracks["audio"] = {"packets": 200, "bytes": 60_000, "first": 12.0}
    observer.keyframes = 5
    observer.nals["h265"].update({33: 5, 34: 5, 19: 5, 1: 90})
    observer.ssrcs["video"] = {615039850}
    observer.ice = {"remote": "192.168.1.18:44004", "type": "host"}
    return observer


def test_report_shape_and_verdicts():
    codec.set_video_codec("h265")
    try:
        report = build_report(observer_with_data(), elapsed=30.0, raw=False)
    finally:
        codec.set_video_codec("h264")
    assert report["codec"] == "h265"
    assert report["announced"]["video_pt"] == 0
    assert report["ice"]["verdict"] == "LAN"
    assert report["tracks"]["video"]["kbps"] == 200  # 750000*8/30/1000
    assert report["keyframes"] == 5
    assert "NOT-A-REAL-ICE-PASSWORD" not in report["answer"]


def test_report_raw_keeps_secrets():
    report = build_report(observer_with_data(), elapsed=30.0, raw=True)
    assert "NOT-A-REAL-ICE-PASSWORD" in report["answer"]


def test_report_relay_verdict():
    observer = observer_with_data()
    observer.ice = {"remote": "34.192.10.9:3478", "type": "relay"}
    report = build_report(observer, elapsed=30.0, raw=False)
    assert report["ice"]["verdict"] == "relay/cloud"


def test_report_survives_an_empty_call():
    report = build_report(Observer(), elapsed=30.0, raw=False)
    assert report["tracks"] == {} and report["ice"] is None
