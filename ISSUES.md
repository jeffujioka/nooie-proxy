# Known issues

## #1 — Live view fails: camera answers the WebRTC offer with `Ret=8`

**Status:** open · **Severity:** blocker

### Summary

A normal run gets all the way through login, camera discovery, p2p registration,
session creation, and sending the offer — but when the camera replies, the
`response.SdpAnswer` carries `Ret=8` and no SDP, so the media handshake never
starts and nothing is recorded. A working client on the same account and camera
gets `Ret=0` and an answer SDP in the same spot.

### Steps to reproduce

```sh
cp .env.example .env        # set NOOIE_USERNAME / NOOIE_PASSWORD
nooie-tui --duration 30
```

### Expected

The camera returns `Ret=0` with a `WebrtcSdp` answer; DTLS-SRTP completes and the
H.264/audio tracks record to `nooie.mp4`.

### Actual

```
selected IPC007_T6S6A3 (online)
registered <uid>: wan <ip>:<port> lan <ip>:<port>
connecting to Nooie signalling WebSocket
creating Nooie WebRTC session
offer sent; waiting for camera answer
...
RuntimeError: camera rejected the call with Ret=8 (data={"Ret": 8, "SessionId": "...", "call_id": "..."})
```

Everything up to the answer succeeds; the camera clearly parses the offer (it
returns a real `SdpAnswer` addressed to our `call_id`/`SessionId`) but declines
it with `Ret=8`.

### Environment

- camera: `IPC007_T6S6A3`, firmware `7.1.71`, EU region
- client: this repo, Python 3.13, aiortc 1.14

### Approaches already tried (no effect — please don't re-tread)

- **p2p NAT registration.** The `getsrv → NatOne → NatGetInfo → PutNatInfo`
  sequence completes and the server acknowledges the published mapping
  (`PutNatInfo` returns success). The call still comes back `Ret=8`, so this step
  is not the missing piece.
- **Offer contents.** The outgoing offer was diffed against a known-good offer
  from a working client: the compact-SDP keys and static values match, and only
  the per-session randoms differ (DTLS fingerprint, ICE ufrag/pwd, SSRCs) — as
  they must. The offer body does not appear to be the cause.
- **`phone_code`.** Tried a stable, device-style `phone_code` (via
  `NOOIE_PHONE_CODE`) instead of a fresh random one per run — no change.
- **Caller token identity.** Substituting a different, independently-valid
  api-token did not change the outcome (and hit unrelated auth errors); the
  identity of the token by itself does not flip `Ret`.
- **Session creation.** `/webrtcsession/user/videocall` returns HTTP 200 /
  `code 1000` with valid STUN/TURN credentials every time; the failure is
  strictly at the `SdpAnswer` stage, not session setup.
