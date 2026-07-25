# progress notes — Ret=8 investigation (claude)

hand-off notes for the `Ret=8` blocker (ISSUES.md #1). another agent (gpt-5.6)
is refactoring signalling in the working tree; this file is diagnosis only and
touches nothing else. all findings below are from live probes against the real
camera (`IPC007_T6S6A3`, fw 7.1.71) plus disassembly of the installed app
(`/Applications/Nooie.app`).

## bottom line

the request path is not the bug. every byte nooie-tui emits — login, device
list, apeman p2p registration, `/webrtcsession/user/videocall`, the wss auth,
and the `service.SdpOffer` envelope/data/SDP — is byte-equivalent to the
official app (confirmed by disassembling the app's offer builder and videocall
request). the camera nonetheless answers `response.SdpAnswer {Ret:8}` with no
SDP. **`Ret=8` is a device/cloud-side call-admission rejection that is
independent of anything we send.** do not keep tuning the offer.

## what was proven (with evidence)

- **content-independent.** identical `Ret=8` for: compact SDP vs full plain
  SDP; `Prepare=1`; `TrickleICE=1`; adding the device `ic`; `origin` 0/1/2;
  `Action` 0/1/2; `CodecMode=0`; **a bogus `SessionId`**; empty ICE creds; no
  trickle candidates. if any field mattered, plain-vs-compact alone would
  differ. it doesn't. (`/tmp/nooie_variants.py`, `nooie_diff.py`, `nooie_env.py`)
- **bogus == valid.** a garbage `SessionId` gets the same `Ret=8` at the same
  latency → the cloud is not validating the session before replying; the device
  is not matching the offer to a pending call.
- **~430 ms, `time:0`.** the answer carries `time:0` and comes back in ~0.4 s —
  looks cloud-synthesised / a short device round-trip, not a media failure.
- **device never contacts us.** with the apeman UDP socket held open and
  watched, the camera sends **zero** packets to our published WAN mapping during
  a call → it never even attempts p2p/ICE to us; the rejection is upstream of
  media. (`/tmp/nooie_watch.py`)
- **not contention.** the official app is installed and running (pid varies) but
  idle — `lsof` shows no sockets from it to the camera/relay/TURN — so it is not
  holding a single-viewer slot.
- **resend / refresh don't help.** `/webrtcsession/user/refresh` returns
  `code 1000`, but resending the offer (same session or after refresh) still
  yields `Ret=8`. no reverse `service.SdpOffer` from the device ever arrives —
  the flow is not caller-answers-device. (`/tmp/nooie_resend.py`)
- **no missing pre-message.** sending `service.SyncTime`, `service.Switch`
  (Action 0/1), or `atr.get` before the offer does not flip it.
  (`/tmp/nooie_pre.py`)
- **apeman is exact.** the provided `apeman.pcap` decodes cleanly with our own
  codec and matches `apeman.register()` step for step (getsrv→NatOne→NatGetInfo
  →PutNatInfo, same servers `18.184.68.75`/`3.66.105.77`, nattype 5, `Ret 0`).
  the pcap contains *only* the apeman exchange (no TLS/wss/media — it was
  filtered), so it confirms apeman and nothing else.

## app-disassembly facts (so nobody re-derives them)

- offer builder is `-[ZXRTCLocalConnection ...]` region ~`0x101b1b100`; the
  envelope has exactly 8 keys (method,msg_id,ver,time,origin,uuid,device_model,
  data) and `data` has exactly the 16 keys we already send. `Action=2`,
  `origin=1`, `ver="1.0"`, `Timestamp/Quality/EnableSpeaker` come from call-param
  getters (0/default for a live call). we match all of it.
- `/webrtcsession/user/videocall` body is just `{device_id}` (1 key) — same as
  ours. completion → `updateVideoCallSuccess:` → offer. no ring / `atr.post` /
  extra step between videocall and offer.
- only two webrtc HTTP endpoints exist: `webrtcsession/user/videocall` and
  `webrtcsession/user/refresh`. no separate invite/ring endpoint.
- the compact-SDP magic values in `compact_sdp_offer` (`isc:"WMSLo"`,
  `md:"LoVID"/"LoAID"`, etc.) were validated against a known-good app offer;
  they are correct.

## most likely root cause (unverified — needs the working exchange)

the app is heavily MQTT-driven (`mqttChannel:connectState:error:`,
`getMqttConnectState:`, `didVideoWithCallInfo:connectState:p2pType:`). the
device is `mqtt_online=1`. the leading hypothesis is that the camera only admits
a webrtc call from an initiator that holds a **persistent Tuya/Thing MQTT (or
equivalent cloud) presence** the cloud can correlate to the call — a channel
nooie-tui never opens. our short-lived wss is enough to *relay* signalling (we
receive the device's frames) but not to make the device treat us as an
authorised live caller, so it fast-rejects with `Ret=8`. `Ret=8` itself is
almost certainly a Tuya/device webrtc admission code (enum not recovered; device
firmware isn't on this machine).

secondary hypothesis: a live Thing-P2P control session to the device relay
(`hb_domain` p2p13-eu.nooie.com:6116, using `puuid`+`secret`) must exist before
the offer. note the *media* path is direct WebRTC (the answer format carries the
device's `ic` ICE candidate), so P2P — if needed — is a control/admission
precondition, not the media transport.

## the one decisive next step

capture the app's **actual** successful call (wss `service.SdpOffer` +
`response.SdpAnswer{Ret:0}` and whatever precedes it). tooling here is the
blocker: no frida, SIP on (lldb attach to the hardened app fails), the app logs
to a file logger (not os_log), and its data container wasn't locatable without a
broad fs search (out of scope). options for whoever picks this up:
1. mitmproxy + trusted CA + system proxy, then open live view in the app (watch
   for cert pinning);
2. capture on the app's host/router with keys, or a rooted/jailbroken device;
3. reverse `ThingP2PSDK` / the MQTT channel to see the admission handshake.
once the working `service.SdpOffer` context is in hand, diff it against
`/tmp/nooie_probe.py` output — the delta will be the precondition, not a field.

## scratch probes (in /tmp, not committed)

`nooie_probe.py` (dump session + raw frames), `nooie_variants.py`,
`nooie_diff.py`, `nooie_env.py`, `nooie_watch.py` (apeman socket watch),
`nooie_resend.py`, `nooie_pre.py`. all import `nooie_tui` and run against the
live account via `.env`.
