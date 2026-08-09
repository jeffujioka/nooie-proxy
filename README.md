# nooie-proxy

Streams live H.264/AAC from your own Nooie IP camera over its WebRTC path,
without the official app. It authenticates, places the call, and muxes the
result to stdout or a URL; nothing is decoded or re-encoded.

```sh
nooie-proxy | vlc -                              # watch it
NOOIE_OUTPUT=udp://127.0.0.1:5004 nooie-proxy &  # serve it to other tools
ffmpeg -i udp://127.0.0.1:5004 frame%04d.jpg     # attach and detach freely
```

Want this inside Home Assistant instead?
[hass-nooie](https://github.com/ltrgoddard/hass-nooie) is an add-on and
component that run this proxy alongside go2rtc and turn each camera into a
camera entity.

## Install

Python 3.11+:

```sh
uv tool install nooie-proxy      # or: pipx install nooie-proxy
```

From a checkout, with [uv](https://docs.astral.sh/uv/):

```sh
git clone https://github.com/ltrgoddard/nooie-proxy.git
cd nooie-proxy
uv tool install --editable .
```

## Configure

Everything is environmental. Copy `.env.example` to
`~/.config/nooie-proxy/.env` (`~/Library/Application Support/nooie-proxy/.env`
on macOS), `chmod 600` it, and fill it in. Values are read literally; exported
variables win over the dotenv.

| variable | default | meaning |
| --- | --- | --- |
| `NOOIE_USERNAME`, `NOOIE_PASSWORD` | — | account login |
| `NOOIE_COUNTRY_CODE` | `44` | account region |
| `NOOIE_DEVICE_ID` | — | camera to use when the account has several |
| `NOOIE_OUTPUT` | `-` | `-` for stdout, else any path or URL PyAV writes |

`nooie-proxy --list-devices` prints every camera on the account (uuid, name,
model, online). A UUID identifying this install lives beside the dotenv;
don't edit or delete it.

## Stream

Every sink is MPEG-TS with the camera's own H.264/AAC, so a consumer can
attach at any time and sync at the next keyframe (about two seconds). One
process serves one consumer; fan out with `ffmpeg -f tee` or the Home
Assistant add-on. Expect 10–20s to the first frame (logins, P2P registration,
and the WebRTC handshake happen once per call); `-probesize 200000` trims
player probing.

## Service

The proxy exits when the camera ends the call, so run it under a supervisor
that restarts it (launchd/systemd). KeepAlive-style restarts recover dropped
calls; throttle the retry rate to avoid login abuse.

## Design

Three independent handshakes precede each call; each has a module.

| module | |
| --- | --- |
| `cloud` | Nooie REST: login, install registration, camera selection, session |
| `thing` | the bundled Tuya account; UID login and MQTT presence |
| `apeman` | publishes the local NAT mapping on Nooie's P2P network |
| `sdp` | Nooie's compact SDP and ICE dialect, both directions |
| `signalling` | WebSocket envelopes and answer matching |
| `rtc` | aiortc patches: AAC, passthrough, RSA DTLS at 1200 bytes, ICE sizes |
| `stream` | places the call and muxes the tracks |
| `env` | dotenv, install identity, credentials |
| `profile` | the app build this impersonates: endpoints and fingerprint |

Media is muxed as it arrives, so the proxy costs a few percent of one core.
Intended for accounts and cameras you own.
