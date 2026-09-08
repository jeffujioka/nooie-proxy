from nooie_proxy.stream import STALL_REASON, Stallwatch


def test_not_stalled_before_armed():
    watch = Stallwatch(timeout=30)
    assert watch.stalled(1000.0) is False


def test_stalls_after_timeout_without_feeding():
    watch = Stallwatch(timeout=30)
    watch.feed(1000.0)
    assert watch.stalled(1029.0) is False
    assert watch.stalled(1030.1) is True


def test_feeding_resets_the_clock():
    watch = Stallwatch(timeout=30)
    watch.feed(1000.0)
    watch.feed(1025.0)
    assert watch.stalled(1054.0) is False
    assert watch.stalled(1055.1) is True


def test_reason_names_the_timeout():
    assert "30" in STALL_REASON and "video" in STALL_REASON
