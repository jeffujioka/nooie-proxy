# fixtures

- `baby_room_2k.h265` — annex-b hevc elementary stream, ~2.5 s, extracted
  from a real ipc100c call (2304x1296, gop ~2 s, starts on vps/sps/pps/idr).
  regenerate with tools/make_fixtures.py against a capture.
- `compact_answer.json` — the camera's compact sdp answer as observed in
  the 2026-09-08 spike, with every session secret replaced. the shape and
  the `video.pt == 0` / `audio.pt == 96` facts are real.
