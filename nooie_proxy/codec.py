# nooie_proxy/codec.py
"""which video codec the camera sends, decided once per call.

nooie's compact answer names no codec; the payload type is the tell. the
ipc100c (h.265) announces video on the static pt 0, while the h.264 build
this proxy was written against uses the dynamic pt 126. one process places
one call, so the choice is process-global state.
"""

_CODECS = ("h264", "h265")
_video_codec = "h264"


def select_codec(pt: int | None, override: str | None = None) -> str:
    """the video codec implied by the announced payload type.

    ``override`` (from NOOIE_VIDEO_CODEC) wins when it names a known codec;
    anything else falls back to the heuristic rather than failing a call.
    """
    if override in _CODECS:
        return override
    return "h265" if pt == 0 else "h264"


def set_video_codec(name: str) -> None:
    global _video_codec
    if name not in _CODECS:
        raise ValueError(f"unknown video codec {name!r}")
    _video_codec = name


def video_codec() -> str:
    return _video_codec
