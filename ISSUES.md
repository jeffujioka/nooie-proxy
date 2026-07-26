# Known issues

## #1 — Live view fails when the camera returns `Ret=8`

**Status:** open · **Severity:** blocker

### Verified result

The independent client successfully completes:

1. Nooie credential login and `/v2/user/put` install registration;
2. camera discovery;
3. Thing UID token creation and password login;
4. Thing home/device bootstrap;
5. MQTT 3.1.1 TLS connection and account-mailbox subscription;
6. Nooie NAT registration and signalling WebSocket connection;
7. video-call session creation, compact SDP offer, and both host/relay ICE
   candidates.

The camera acknowledges the signalling messages, then returns
`response.SdpAnswer` with `Ret=8` and no answer SDP:

```text
offer sent; waiting for camera answer
...
RuntimeError: camera rejected the call with Ret=8
```

No peer connection is established and no recording is created. The most recent
end-to-end check reproduced this with the official Nooie app confirmed absent.

### Reproduce

Configure both the Nooie account and private Thing SDK material as described in
[README.md](README.md), then run:

```sh
nooie-tui --check-config
nooie-tui --duration 30
```

### What has been ruled out

- **Missing Thing login or MQTT presence.** The raw-RSA UID password operation,
  signed/encrypted mobile API, exact SDK MQTT credentials, TLS broker
  connection, and account subscription all succeed independently.
- **A Tuya-MQTT media path.** The successful official capture uses Nooie's
  `service.SdpOffer` WebSocket path and direct WebRTC media. Its MQTT connection
  only subscribes twice to the account mailbox; it does not publish an RTC
  offer, call `tuya.m.rtc.session.init`, or subscribe to a camera topic.
- **The ordinary post-login bootstrap.** The exact 13-field `/user/put`, Thing
  home-space list, and home device-list calls all succeed. The account has one
  Thing home and no Thing device entries.
- **Offer shape.** After masking only per-session random values, the generated
  compact offer has no differing keys, types, or static values from a captured
  accepted offer. The prefix is the required bare-LF `00\n`; CRLF is rejected.
- **ICE credential lengths and candidates.** All 24 captured official offers
  use a four-character ufrag and 24-character password. The client now matches
  both and emits the observed host and relay candidates on media section zero.
- **Install identity fields.** Controlled tests used the captured stable Nooie
  request UUID, `phone_code`, Thing UUID, iPad model/platform metadata, locale,
  login brand, and `/user/put` brand individually and together. `Ret=8`
  persisted.
- **Read-only UI/device priming.** Ten of twelve captured UI API calls replayed
  successfully; the other two returned ordinary endpoint errors. Six captured
  `atr.get` requests also returned complete camera state. Neither changed the
  answer, so the extra attribute requests were removed from production.
- **WebSocket request shape.** The client supplies SocketRocket's HTTPS
  `Origin` and suppresses aiohttp's extra `Accept`, `Accept-Encoding`, and
  `User-Agent` headers. The server still acknowledges every message and the
  camera still returns `Ret=8`.
- **An unobserved relay bootstrap.** Every external flow in the successful
  official capture is accounted for. There is no separate port-6116 connection
  or hidden MQTT publish during live-view setup.

The official diagnostic log contains six accepted live-view sequences. It also
contains one `Ret=8` answer several minutes after the first accepted sequence,
with no adjacent new offer or immediate retry, so that occurrence does not
establish a retry-based fix.

### Remaining boundary

There is no known unmatched HTTP, MQTT, NAT, WebSocket, SDP, or ICE event before
the answer. The remaining difference is therefore below the observable request
sequence: native client state or fingerprinting, or an opaque backend/camera
admission rule.

A useful next experiment must isolate that boundary—for example, drive the same
captured request sequence through the native SocketRocket/Network.framework
stack, or instrument the iOS call path immediately before `service.SdpOffer`.
Repeating Thing bootstrap calls, SDP tuning, UI GETs, or generic Tuya RTC
signalling would re-test paths already disproved by the captures.

Detailed chronology and sanitized evidence are recorded in
[PROGRESS.md](PROGRESS.md). No account tokens, passwords, camera identifiers,
or Thing SDK secrets are stored in these documents.
