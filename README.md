# nooie-proxy

Your own Nooie IP camera has a WebRTC path but no RTSP output. nooie-proxy
uses that path to stream live H.264 and AAC, without the official app. The
proxy signs in, places the call, and muxes the result to stdout or to a URL.
It does not decode or re-encode the media.

```sh
nooie-proxy | vlc -                              # watch it
NOOIE_OUTPUT=udp://127.0.0.1:5004 nooie-proxy &  # serve it to other tools
ffmpeg -i udp://127.0.0.1:5004 frame%04d.jpg     # attach and detach freely
```

To use this in Home Assistant instead, see
[hass-nooie](https://github.com/ltrgoddard/hass-nooie). It is an add-on and
component that run the proxy with go2rtc. Each camera becomes a camera
entity.

## Install

The proxy needs Python 3.11 or later.

```sh
uv tool install nooie-proxy      # or: pipx install nooie-proxy
```

To install from a checkout, use [uv](https://docs.astral.sh/uv/):

```sh
git clone https://github.com/ltrgoddard/nooie-proxy.git
cd nooie-proxy
uv tool install --editable .
```

## Configure

The proxy reads its configuration from the environment. Copy `.env.example`
to `~/.config/nooie-proxy/.env`, or to
`~/Library/Application Support/nooie-proxy/.env` on macOS, then `chmod 600`
it. The proxy reads the values literally. An exported variable replaces the
value in the file.

| variable | default | meaning |
| --- | --- | --- |
| `NOOIE_USERNAME`, `NOOIE_PASSWORD` | — | the account login |
| `NOOIE_COUNTRY_CODE` | `44` | your mobile phone's country code |
| `NOOIE_DEVICE_ID` | — | the camera to use when the account has more than one |
| `NOOIE_OUTPUT` | `-` | `-` for stdout, or any path or URL that PyAV writes |

`nooie-proxy --list-devices` prints the UUID, name, model, and online state
of every camera on the account. The proxy also stores a UUID beside the
dotenv to identify this install. Do not edit or delete it.

## Sessions

The proxy stores its Nooie session in `sessions.json` beside the identity and
reuses it, so a restart signs in again only when the account refuses what it
holds. This keeps a camera that retries from becoming a login loop. The file
holds session secrets, and the proxy writes it with the same permissions as
the identity. Delete it to sign in from nothing.

Nooie's signalling holds one websocket for each install, and a second
connection closes the first. Two proxies that share a state directory
therefore end each other's calls. To run more than one, give each its own
`XDG_CONFIG_HOME`, or on macOS its own `HOME`.

## Stream

Every sink carries MPEG-TS with the camera's own H.264 and AAC. As a result, a
consumer can attach later and synchronize at the next keyframe, which takes
about two seconds. One process serves one consumer. To serve more, use
`ffmpeg -f tee` or the Home Assistant add-on.

The first frame arrives 10 to 20 seconds after the start. The login, the P2P
registration, and the WebRTC handshake each occur once for every call. The
option `-probesize 200000` reduces the time a player spends on probing.

## Service

The proxy exits when the camera ends the call, so run it with a supervisor
that restarts it, such as launchd or systemd. A restart recovers a dropped
call. Limit the retry rate to avoid too many login attempts.

## Design

Two independent handshakes precede each call, and each one has a module.

| module | contents |
| --- | --- |
| `cloud` | the Nooie REST API: login, registration, camera selection, session |
| `apeman` | publishes the local NAT mapping on the Nooie P2P network |
| `sdp` | the compact Nooie SDP and ICE dialect, in both directions |
| `signalling` | the WebSocket envelopes and the answer matching |
| `rtc` | the aiortc patches: AAC, passthrough, RSA DTLS at 1200 bytes, ICE sizes |
| `stream` | places the call and muxes the tracks |
| `env` | the dotenv, the install identity, and the credentials |
| `cache` | the stored sessions, so a restart does not sign in again |
| `profile` | the app build the proxy presents itself as |
| `service` | the command line entry point |
| `twofish` | the cipher the apeman RPC uses |

The proxy muxes the media as it arrives, so it costs a few percent of one
core. Use it only with accounts and cameras that you own.
