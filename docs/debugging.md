# Debugging a Nooie camera stream

## First stop: --diagnose

    nooie-proxy --diagnose --seconds 30 [--json] [--raw]

WARNING: Nooie holds one signalling connection per install — disable the
Home Assistant integration first, and close the official app.

Read the report in this order:

1. `announced.video_pt` — 0 means the camera declares the h.265 dialect;
   126 means h.264. `codec` shows what this proxy chose (override with
   `NOOIE_VIDEO_CODEC=h264|h265`).
2. `nal_histogram` — a healthy h.265 call shows VPS/SPS/PPS/IDR at the GOP
   cadence (~every 2 s) and TRAIL slices in between. A histogram dominated
   by one meaningless type usually means the codec label is wrong.
3. `keyframes` — 0 with traffic flowing = wrong depacketizer or the camera
   never got a keyframe request.
4. `ice.verdict` — LAN means media flows camera→host directly (cheap);
   relay/cloud means it crosses the internet.
5. `tracks.*.first_after_s` — beyond ~20 s points at signalling problems.

## Packet capture (when --diagnose is not enough)

RTP payloads are SRTP-encrypted; headers are not. Payload types and SSRCs
are readable on the wire:

    sudo tcpdump -i <iface> -n 'udp and host <camera-ip>' -w /tmp/cam.pcap

Payload type histogram (python, stdlib only) — RTP begins after the
42-byte Ethernet+IP+UDP headers; version bits 0x80..0xBF, PT = byte1 & 0x7f,
SSRC = bytes 8..12. In the 2026-09-08 spike the camera sent video on PT 0
(6088 packets) and audio on PT 96 (1206 packets); stock aiortc dropped PT 0
on the floor — that is fix `_adopt_remote_payload_types` in rtc.py.

## Known failure shapes (2026-09-08 spike)

| Symptom | Cause | Recovery |
|---|---|---|
| answers, connects, 0 video packets, drops in 1–3 s | camera's small call pool clogged by half-open calls (non-SIGTERM shutdowns) | power-cycle the camera |
| audio fine, video 0 kbps | payload type 0 dropped (bug 1) | fixed in this fork |
| video flows, 0 keyframes, undecodable | h.265 parsed as h.264 (bug 2) | fixed in this fork |
| second run kills the first | one signalling websocket per install | run one thing at a time |
