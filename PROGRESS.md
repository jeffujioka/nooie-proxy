# Progress: `Ret=8` / independent Thing login

Updated: 2026-07-26 19:20 BST

## Current state

Live video is still blocked: the CLI reaches `response.SdpAnswer`, but the
camera returns `Ret: 8` without SDP.

The independent Thing/Tuya implementation is now complete and live-validated.
The CLI reproduces the SDK 5.7.10 UID login, persists a private Thing device
identity, connects to the regional MQTT/TLS broker with the recovered exact
credentials, subscribes to the account mailbox, and performs the observed home
bootstrap. It then completes Nooie login, install registration, discovery, NAT
registration, WebSocket setup, video-call session creation, and offer/candidate
delivery without the official app running.

The camera still returns `Ret=8`. Exact identity substitutions, ordinary UI
bootstrap calls, device attribute reads, offer normalization, ICE credential
lengths, SocketRocket `Origin`/header shape, and MQTT/HTTPS ordering have all
been tested without changing that result. The successful official capture has
no additional HTTP, MQTT, NAT, WebSocket, or relay event left unmatched before
its accepted answer. The remaining boundary is native client state or
fingerprinting, or an opaque backend/camera admission rule.

The sections below are a chronological research log. Later checkpoints
supersede hypotheses in earlier entries where they conflict.

## Decisive evidence from the fresh login

Capture: `nooie-official-login-live.pcap` (about 1.5 MB / 2,265 packets).

The successful official login on 2026-07-26 followed this sequence:

```text
13:49:57.019  Nooie /login/login request
13:49:57.198  Nooie login response
13:49:57.236  internal route yrcx://yrtuyaaccountservice/c/loginnooie
13:49:57.237  Tuya smartlife.m.user.uid.token.create
13:49:57.336  Tuya smartlife.m.user.uid.password.login
13:49:57.468  TCP/TLS connection begins to m1.tuyaeu.com:8883
```

The two Tuya HTTP calls go to `https://a1.tuyaeu.com/api.json`. The token-create
request body is 855 bytes and its JSON response body is 966 bytes. The UID login
request body is 1,361 bytes and its JSON response body is 2,014 bytes. The MQTT
connection is established before the later video offer and remains alive after
leaving live view.

Static Objective-C metadata establishes the credential mapping:

```text
YRTuyaAccountService loginnooie
  -> decrypt routed password (app routing key: osaio123ABC)
  -> ThingSmartUser loginByUid:password:countryCode:
```

The values supplied are the Nooie UID, the user's Nooie password, and the
normal country code. This matches Tuya's documented UID-login bridge for apps
that retain their own account system:

https://developer.tuya.com/en/docs/app-development/iOS-user-uid?id=Kaixtsekab9s1

## What is now ruled out

- **A busy camera is not the general cause.** A known-idle run still returned
  `Ret=8`.
- **Nooie token freshness alone is not enough.** Reusing the exact current
  official-app Nooie token with a separate `phone_code` produced a stable
  signalling WebSocket but still returned `Ret=8`.
- **Account-level MQTT presence is not enough.** That test ran while the
  official app's Tuya MQTT connection was alive. The CLI still failed, implying
  that admission is tied to the caller/device's own Thing session or identity.
- Reusing the official token with the same `phone_code` displaced the app's
  WebSocket. Nooie allows only one signalling connection per phone identity.
- Full/compact SDP, offer fields, candidate variants, session refresh/resend,
  bogus session IDs, pre-offer signalling messages, and exact Apeman NAT
  registration did not change `Ret=8`.

The remaining leading explanation is that the camera/cloud expects the caller's
own authenticated Thing session and MQTT presence before accepting its WebRTC
offer.

## Validated Tuya wire format

The official app uses Thing SDK 5.7.10 and the modern form-urlencoded mobile
API dialect. The captured logged-out login requests each have 26 fields:

```text
a, v, time, requestId, clientId, deviceId, sign, postData,
sdkVersion, deviceCoreVersion, appVersion, appRnVersion,
bundleId, channel, os, osSystem, platform, lang, timeZoneId,
ttid, et, nd, cp, lat, lon, bizData
```

`sid` is optional and absent from these two logged-out calls. `bizData` is
ordinary JSON transport metadata, not the encrypted business payload.

The signing and payload algorithms have now been validated against the
preserved SDK 5.7.10 vectors:

```python
SIGNED_FIELDS = {
    "a", "v", "lat", "lon", "et", "lang", "deviceId", "imei",
    "imsi", "appVersion", "ttid", "isH5", "h5Token", "os",
    "clientId", "postData", "time", "n4h5", "sid", "sp", "requestId",
}

digest = md5(encrypted_post_data).hexdigest()
post_hash = digest[8:16] + digest[0:8] + digest[24:32] + digest[16:24]

feed = "||".join(
    f"{key}={post_hash if key == 'postData' else params[key]}"
    for key in sorted(SIGNED_FIELDS)
    if key in params and params[key] != ""
)

signing_key = f"{bundle_id}_{secret_pic_key}_{app_secret}"
sign = hmac_sha256(signing_key, feed).hexdigest()
```

The captured token-create signature matches this formula exactly. There is no
trailing app secret or separator in the HMAC message.

For the ordinary `ThingRequest` path used by these login calls:

```python
key_material = f"{bundle_id}_{secret_pic_key}_{app_secret}"
if ecode:
    key_material += f"_{ecode}"

aes_key = hmac_sha256(request_id, key_material).hexdigest()[:16].encode()
encrypted = base64(AES-128-ECB-PKCS7(aes_key, json_payload))
```

The earlier AES-GCM hypothesis applied to the SDK's separate Fusion/Highway
request classes, not to these `/api.json` login vectors. Both the request
`postData` and response `result` use AES-128 ECB with PKCS#7 padding here. The
logged-out calls use no `ecode`.

## Volatile forensic evidence

The app's CFURL cache journal preserved the otherwise non-cacheable login calls:

```text
~/Library/Containers/FDBC4DD6-B852-4325-B9DE-0A4F6BFE2E81/
  Data/Library/Caches/com.nooie.home/Cache.db-wal
```

Useful current-login records:

```text
offset 728300  token-create request, requestId 5ED11BA2-...-E5995830E995
offset 731466  token-create encrypted response
offset 769004  UID-login request, requestId 92419E67-...-B64F3F46B4B8
offset 771617  UID-login encrypted response
offset 992008  first authenticated call carrying the new sid
```

The full UUIDs can be recovered from the journal. Do not paste the full request
or response blobs into the repository: the decrypted login response will
contain reusable Thing/MQTT credentials. The journal is volatile and may be
overwritten when Nooie runs again.

The evidence has now been copied out of the live container to a mode-0700
directory:

```text
~/Library/Application Support/nooie-tui-forensics/
  20260726-1545-login-cache/
```

This private snapshot contains the cache database/WAL, the original encrypted
diagnostic log, its mode-0600 decrypted copy, the app configuration and bitmap,
the public signing certificates, and a copy of the prior 16-snapshot workspace.
The isolated request/response vectors are under
`prior-session-workspace/vectors/`. It is no longer necessary to rely on the
live WAL or `/private/tmp` copy.

A passive SQLite WAL checkpoint was invoked at about 14:06 BST while inspecting
the cache. The journal still existed afterward at 1,297,832 bytes and retained
the records above.

## Installed app and SDK findings

At the stop point, the App Store build was:

```text
bundle id:       com.nooie.home
version:         3.7.0
Thing SDK:       5.7.10
ephemeral path:  /private/var/folders/.../Wrapper/Nooie.app
```

`thing_custom_config.json` contains the Thing app ID, scheme, and public app
key. The request `clientId` is different from that public app key. Do not commit
either app credential into source until its role and redistribution implications
are understood.

The main binary contains references to:

```text
appEncryptKeyProd
appEncryptSecretProd
thingAppSecret
keyCertSign
genKey:token:secretKey:appSecretPicKey:bundleId:
generateKey:session:secretKey:appSecretPicKey:bundleId:
```

This trail has now been completed. The request `clientId` and corresponding
32-character SDK app secret are present together in the executable. Their
values are intentionally omitted from this file.

Persisted Thing state is also encrypted:

- `kDefaultThingUserV4`: 1,120-byte blob in `com.nooie.home.plist`;
- `kCertificateKey_V2`: base64 text decoding to 6,960 bytes;
- keychain access group: `DX4USQYJ9S.com.nooie.home`.

`kDefaultThingUserV4` has now also been decrypted. The SDK uses AES-256 CBC,
a zero IV, and PKCS#7 padding; its 32-byte storage key is held in the executable
under the same small XOR-obfuscated-string mechanism used elsewhere. The
plaintext is the expected Thing user JSON, including `sid`, `ecode`, `uid`,
`username`, domain information, and profile fields. No values from that JSON
have been placed in the repository.

## Encrypted Nooie diagnostic log

The fresh login is in:

```text
~/Library/Containers/FDBC4DD6-B852-4325-B9DE-0A4F6BFE2E81/
  Data/Documents/2026-07-26 13-16-50_yrlog_dr.log
```

The file uses Twofish ECB over 16-byte blocks with:

```python
b"thIsIStEofishLOGkEy!thIsIStEofis"
```

The temporary `twofish==0.3.0` install exists only in `.venv`; it was not added
to project dependencies. Never dump the decrypted log wholesale: it contains
Nooie credentials, live tokens, user IDs, and device identifiers.

## Existing signalling patch

`nooie_tui/client.py` remains modified with evidence-based signalling changes:

- per-call message IDs and the official pre-call empty `service.Close`;
- corrected `service.Switch` field (`time`, not `tme`);
- TURN credentials passed to aiortc and BUNDLE-aware candidate selection;
- official-style host/relay candidate formatting;
- correct compact-SDP marker and media coordinates;
- official-length ICE credentials.

`tests/test_signalling.py` covers those behaviours. The last recorded checks
passed:

```text
Ran 5 tests in 0.000s
OK
python -m compileall -q nooie_tui
```

These changes are not a `Ret=8` fix by themselves.

## Next steps at the original handoff

1. Recover and validate the password transform used between
   `uid.token.create` and `uid.password.login` (the decrypted request contains
   `passwd`, `ifencrypt`, the returned `token`, and `options.group`).
2. Trace the post-login MQTT credential/client-ID derivation and exact
   subscriptions from SDK 5.7.10. The login result already supplies `sid`,
   `ecode`, username, and the regional MQTT/MQTTS endpoints and ports.
3. Implement a dedicated Thing client that persists its own device identity,
   performs token creation and UID/password login, opens TLS MQTT, waits for
   successful CONNACK/subscription, and only then starts the Nooie video-call
   flow.
4. Add deterministic tests from sanitized versions of both captured vectors;
   no reusable account, session, device, or app secret may enter fixtures.
5. Test end-to-end with the official app fully quit/logged out. Success means
   the CLI independently obtains its Thing session, connects to
   `m1.tuyaeu.com:8883`, and receives `SdpAnswer Ret=0`.

## Worktree at the original handoff

No commit was created.

```text
 M nooie_tui/client.py
?? PROGRESS.md
?? apeman.pcap
?? nooie-official-login-live.pcap
?? tests/test_signalling.py
```

`CLAUDE-PROGRESS.md` and `GPT-PROGRESS.md` were removed as superseded. `README.md`
and `ISSUES.md` remain as project documentation.

Encrypted official-app logs contain live credentials. Extract and redact only
the fields needed for comparison; do not publish full decrypted logs.

## Continuation checkpoint — 2026-07-26, fresh login capture

At the user's request, progress is now appended to this file during every
working turn so the investigation can resume safely after an interruption.

A watcher was armed before a fresh official-app logout/login. It captured 16
successive CFURL-cache WAL states in a private mode-0700 directory outside the
repository:

```text
/private/tmp/nooie-tui-tuya.ycOCvG/
```

The two required authenticated test vectors are now preserved:

- `snapshot-0001`: `smartlife.m.user.uid.token.create`, 855-byte request
  body and 966-byte response body;
- `snapshot-0002`: `smartlife.m.user.uid.password.login`, 1,361-byte
  request body and 2,014-byte response body.

The isolated request archives and response bodies are under the private
`vectors/` subdirectory. They have not been added to the worktree. Each request
has 26 form fields; `postData` decodes to 48 bytes for token creation and 400
bytes for UID login. The encrypted response `result` values decode to 672 and
1,456 bytes respectively. Both responses have only `result`, `sign`, and `t`
at the JSON top level.

Static analysis made a significant advance. The App Store executable is about
52.8 MB and only one 4 KiB page is FairPlay-encrypted
(`cryptoff=1585152`, `cryptsize=4096`). The relevant key-derivation methods are
outside that page and can be disassembled. Objective-C metadata identifies:

```text
ThingSecurityUtil
  + genKey:token:secretKey:appSecretPicKey:bundleId:
  + generateKey:session:secretKey:appSecretPicKey:bundleId:
  + shuffleToken:prelen:
  + cryptoSha256:secret:
```

The first two methods have identical bodies. The recovered algorithm is:

1. Build `bundleId + "_" + appSecretPicKey + "_" + secretKey`.
2. If `token`/`session` is non-empty, take its first 16 characters and map each
   character `c` to `token[ord(c) % 16]`; append that 16-character shuffle to
   the material with an underscore.
3. Compute HMAC-SHA256 over that material, using the first method argument as
   the HMAC key.
4. Hex-encode in lowercase and take the first 16 characters.

The order in step 1 follows Darwin arm64's stack convention for Objective-C
variadic arguments and the method's `%@_%@_%@` format. `cryptoSha256:secret:`
calls `CCHmac` with algorithm 2 (SHA-256) and emits bytes with `%02x`.
`shuffleToken:prelen:` was also reconstructed instruction by instruction.

This formula is structurally recovered but not yet authenticated against an
AES-GCM tag. The next task is to locate callers of the two public derivation
methods, identify which captured field supplies the first argument and which
persisted/generated values supply `secretKey` and `appSecretPicKey`, then
validate candidate keys against both response vectors. A whole-binary radare2
cross-reference pass was abandoned after it remained non-responsive; use a
targeted ARM64 selector-reference scan instead.

## Continuation checkpoint — 2026-07-26, certificate and security-image tracing

The targeted ARM64 selector-reference scan succeeded where the whole-binary
radare2 analysis did not. It resolved the selector stubs and all four relevant
call sites:

```text
genKey:       stub 0x101f1f800, calls 0x1016359a8 and 0x101636a48
generateKey:  stub 0x101f1ff20, calls 0x101633a28 and 0x101634950
```

Register/data-flow tracing at those callers confirms that the derivation is
wired to the request-scoped first argument plus
`ThingCustomConfig.secretKey`, `.secretPicKey`, and `.bundleId`. This closes
the earlier caller-mapping question, although the resulting key has still not
been authenticated against either preserved AES-GCM vector.

The relevant persisted defaults were copied into the existing private
mode-0700 workspace:

```text
/private/tmp/nooie-tui-tuya.ycOCvG/state/
```

Static analysis found the `kCertificateKey_V2` decryptor and its 32-byte
internal AES key. The key is stored in the executable under a simple in-place
XOR obfuscation; its raw value has deliberately not been written here. Tracing
the `thingsdk_aes256DecryptWithKey:` wrapper allowed the certificate state to
be decrypted offline:

```text
input text:  9,280 hexadecimal characters
ciphertext:  4,640 bytes
plaintext:   4,634 bytes of JSON
root:        list with 16 entries
output:      state/certificate-v2.json
```

This corrects the earlier provisional base64 interpretation of
`kCertificateKey_V2`: the SDK treats the stored text as hex, producing 4,640
ciphertext bytes. The decrypted data is a collection of domain/certificate
records and did not directly expose the `secretKey` or `secretPicKey`.
`kDefaultThingUserV4` remains an unopened 1,120-byte high-entropy archive.
None of these private state artifacts has been added to the repository.

Objective-C metadata and initialization flow further identify:

```text
YRAppConfiguration
YRNooieConfiguration
YRNooieCNConfiguration
YROsaioConfiguration
tyappKey
tyappSecret
startWithAppKey:secretKey:
```

The Nooie configuration supplies the ordinary app key/secret side of SDK
startup. The remaining hidden picture-key path leads to the installed bundle:

```text
/Applications/Nooie.app/Wrapper/Nooie.app/
  ThingSmartCryption.bundle/t_s.bmp
```

The SDK locates that asset using the names `ThingSmartCryption`, `t_s`,
`thingsdk`, and `bundlecfg`. The recovered path takes the first string decoded
from the bitmap, converts its hexadecimal pairs to bytes, and constructs a
UTF-8 string. That output is the strongest current lead for
`ThingCustomConfig.secretPicKey`.

Two public reverse-engineering implementations were found that document the
same Tuya/Thing security-image format:

- `nalajcie/tuya-sign-hacking`, especially `read-keys-from-bmp/read_keys.c`
  and `coeffs_to_key.c`;
- `eisbaw/babymonitor-client`, especially
  `re/scripts/bmp_token_ghidra.py` and the adjacent Ghidra-derived routines.

The latter is described as a byte-exact Python port of the bitmap
imath/bignum-and-matrix decoder. A local validation harness was started using
the app-key CFString located in the Nooie executable and the installed
`t_s.bmp`, but the harness failed before producing decoder output. Therefore no
bitmap-derived key has yet been claimed or recorded.

The next concrete steps are:

1. Repair the decoder harness and run the byte-exact implementation against
   the installed `t_s.bmp`, initially recording only output lengths and hashes.
2. Confirm which decoded field becomes `secretPicKey`, and finish mapping the
   Nooie `tyappSecret` value to `ThingCustomConfig.secretKey`.
3. Recompute the recovered `ThingSecurityUtil` derivation for both preserved
   vectors and accept a candidate only when AES-GCM tag verification succeeds.
4. Decrypt and inspect only the minimum login fields needed for the client,
   keeping reusable account and MQTT credentials out of the repository.

## Continuation checkpoint — 2026-07-26 16:39 BST, crypto validated

This checkpoint supersedes the provisional AES-GCM and unopened-bitmap notes
above. No secret value, password, token, session, user ID, or device ID is
included here.

### Evidence preservation

The live cache contents and the surviving `/private/tmp` analysis workspace
were copied to:

```text
~/Library/Application Support/nooie-tui-forensics/
  20260726-1545-login-cache/
```

Directory permissions are `0700`; decrypted/sensitive files are `0600`.
Important contents are:

```text
Cache.db, Cache.db-wal, Cache.db-shm
2026-07-26 13-16-50_yrlog_dr.log
2026-07-26 13-16-50_yrlog_dr.decrypted.log
t_s.bmp
thing_custom_config.json
signing-cert-0, signing-cert-1, signing-cert-2
prior-session-workspace/vectors/
prior-session-workspace/state/
thing-material.private.json
```

`thing-material.private.json` is outside the repository and mode `0600`. It
contains the extracted app key, app secret, picture key, bundle ID, public
certificate hashes, and version metadata. It must never be copied into a
fixture, issue, log, commit, or final user-facing output.

### SDK 5.7.10 bitmap format and `secretPicKey`

The installed stable bundle is
`/Applications/Nooie.app/Wrapper/Nooie.app`; the security image is
`ThingSmartCryption.bundle/t_s.bmp` (100x75, 24-bit BMP, 22,554 bytes).

The older public decoder failed because SDK 5.7.10 uses bitmap format version
2. Targeted disassembly of the native reader at `0x101504a08` recovered the
format:

1. Compute the signed Java-style `31 * hash + char` app-key hash, take its
   absolute value, then use `(hash % pixel_length) // 2`.
2. The byte at that pixel index is the format version (`2`).
3. Subsequent logical bytes are encoded in the low bit of eight consecutive
   pixel bytes, least-significant bit first.
4. The header gives one output key and four polynomial point pairs.
5. Each point is encoded as a byte length followed by LSB-packed bytes. In this
   image, each x-coordinate is four bytes and each y-coordinate is 32 bytes.
6. Arbitrary-precision rational interpolation at x=0 produces a 32-byte
   constant.
7. Format version 2 passes those bytes through an additional fixed native
   24-byte-block transform at `0x101505710`.

The transform was executed offline under temporary ARM64 emulation, using only
the relevant code/constant pages from the installed executable. Its output is
valid printable UTF-8 of length 32, matching the `ThingSmartCore` conversion
path. This is the validated `secretPicKey`. The temporary Unicorn package is
under `/tmp/nooie-unicorn-20260726`; it is not a project dependency.

The request `clientId` is the real SDK startup app key. It differs from the
public-looking `thingAppKey` in `thing_custom_config.json`. The matching
32-character SDK app secret is stored adjacent to the client ID in the
executable. Both are retained only in the private material file.

### Exact signature reproduction

The token-create request's 64-character HMAC-SHA256 signature now reproduces
exactly. The signed whitelist is:

```text
a, v, lat, lon, et, lang, deviceId, imei, imsi, appVersion, ttid,
isH5, h5Token, os, clientId, postData, time, n4h5, sid, sp, requestId
```

Only present, non-empty values are included, sorted by field name and joined
with `||`. Before inclusion, `postData` is replaced by the rearranged lowercase
MD5:

```text
md5[8:16] + md5[0:8] + md5[24:32] + md5[16:24]
```

The HMAC key is:

```text
bundleId + "_" + secretPicKey + "_" + appSecret
```

There is no secret suffix in the HMAC message.

### Exact login-payload encryption and decrypted vector shapes

The captured login calls use the ordinary `ThingRequest` class, not the
Fusion/Highway AES-GCM classes. Static tracing and vector validation establish:

```text
keyMaterial = bundleId + "_" + secretPicKey + "_" + appSecret
if ecode is non-empty:
    keyMaterial += "_" + ecode

digest = HMAC-SHA256(key=requestId, message=keyMaterial).hexdigest()
aesKey = first 16 ASCII characters of digest
cipher = AES-128 ECB with PKCS#7 padding
wireValue = standard Base64(ciphertext)
```

Using an empty `ecode` authenticates and decrypts all four captured encrypted
values:

- token-create request `postData`;
- token-create response `result`;
- UID-login request `postData`;
- UID-login response `result`.

The decrypted token-create request contains only `uid` and `countryCode`. Its
decrypted result wrapper contains `result`, `status`, `success`, and `t`; nested
`result` contains:

```text
exponent, pbKey, publicKey, token
```

The decrypted UID-login request contains:

```text
uid, countryCode, passwd, ifencrypt, token, options
options.group
```

The decrypted UID-login response uses the same wrapper and its nested `result`
contains:

```text
accountType, attribute, dataVersion, domain, ecode, email, extras,
headPic, mobile, nickname, partnerIdentity, phoneCode, receiver,
regFrom, sex, sid, snsNickname, tempUnit, timezone, timezoneId,
uid, userAlias, userType, username
```

The session field lengths agree with the persisted model (`sid` 56 characters,
`ecode` 16, UID 20, username 16). `receiver` is empty in this response.
`domain` contains 24 regional endpoints/settings, including `mobileMqttUrl`,
`mobileMqttsUrl`, `mobileMediaMqttUrl`, `mqttPort`, `mqttsPort`,
`mqttQuicUrl`, `fusionUrl`, and API/media URLs. Values are deliberately omitted.

### Persisted Thing user state

The 1,120-byte `kDefaultThingUserV4` blob is no longer opaque. The storage key
comes from a 32-byte executable constant decoded by the native one-byte XOR
string helper. Decryption is:

```text
AES-256 CBC
zero 16-byte IV
PKCS#7 padding
UTF-8 JSON plaintext
```

The resulting keys match the UID-login user model, including `sid`, `ecode`,
`uid`, `username`, domain, extras, and profile fields. This independently
confirms the login response interpretation. The decrypted object was inspected
in memory only; the preserved encrypted blob remains sufficient to reproduce
the check.

### Immediate continuation point

The next unresolved protocol step is no longer request crypto. It is:

1. Reproduce the UID password transform. The token-create result supplies RSA
   material plus a token; the UID-login request sends an encrypted `passwd`
   with `ifencrypt`.
2. Trace SDK 5.7.10 MQTT connect parameters after the successful user reset:
   client ID, username/password derivation, TLS settings, clean-session/keepalive
   values, and subscriptions.
3. Only then add `nooie_tui/thing.py`, integrate it before video signalling,
   create sanitized deterministic tests, and perform the official-app-quit
   end-to-end test.

No source implementation was made during this forensic checkpoint.

## 2026-07-26 — independent Thing login/MQTT implementation checkpoint

The previously unresolved protocol work has now been implemented far enough
to reach the Thing UID-login password check against the live service.

### Recovered iOS SDK behavior

Static analysis of the bundled Thing SDK 5.7.10 recovered the remaining MQTT
configuration without relying on the official app at runtime:

- TLS broker host and port come from the UID-login response's
  `mobileMqttsUrl` and `mqttsPort`;
- MQTT uses protocol 3.1.1, a 60-second keepalive, and a clean session;
- the legacy iOS client ID, username, and password derivations have been
  reproduced exactly, including the SDK's nested-MD5 slices;
- the account subscription is `<partnerIdentity>/mb/<thingUid>`;
- the device inbound topic is `smart/mb/in/<deviceId>`.

The UID-login password field is RSA PKCS#1 v1.5 encryption of the lowercase
ASCII MD5 digest expected by the Thing SDK, encoded as lowercase hexadecimal
ciphertext.

### Source implementation

Added `nooie_tui/thing.py` with:

- exact 26-field Thing request construction and HMAC signing;
- AES-128-ECB request/response encryption;
- token creation and UID/password login;
- persistent, app-independent Thing device identity stored outside the
  repository with private permissions;
- the recovered iOS MQTT credential derivation;
- TLS MQTT connection and account/device subscriptions.

Integrated this bootstrap into `nooie_tui/client.py` so Nooie discovery is
followed by Thing login and MQTT presence before WebRTC signalling. Added
`aiomqtt` and `cryptography` as locked runtime dependencies.

App credentials remain outside the repository. No private key material,
account password, session token, or derived MQTT credential has been written
to this file or source control.

### Verification status

- dependency resolution and environment synchronization succeeded;
- the new modules compile;
- Nooie account login and camera discovery still succeed;
- a live Thing token-create request authenticates and decrypts successfully,
  proving the app identity, request signature, transport encryption, and
  request profile;
- the first live UID-login attempt reached the service but returned
  `USER_PASSWD_WRONG`.

That last result isolates the remaining issue to the bridge between Nooie's
already-MD5 password representation and Thing's own password hashing step.
The evidence indicates that the Nooie bridge supplies its MD5 digest to the
Thing SDK, producing a double-MD5 value before RSA encryption. This has not yet
been committed as the final behavior or retried against the live account.

### Immediate continuation point

1. Validate the double-MD5 bridge with one staged live UID-login attempt.
2. If accepted, lock that behavior into sanitized deterministic unit tests.
3. Establish TLS MQTT CONNACK and verify the required subscriptions.
4. Quit the official Nooie app and run the complete independent camera path,
   confirming WebRTC `Ret=0` and a playable recording.
5. Run the full test suite, configuration checks, and a secret-leak scan, then
   append the final result here.

## 2026-07-26 — web research: are we on the wrong a/v transport?

Research-only checkpoint (no code changed). The question was whether `Ret=8`
persists because the a/v is meant to arrive over a completely different path
than the Nooie signalling WebSocket we currently offer on. The short answer is
that this is the most likely single cause, and there is a documented, working
open-source recipe for the correct path.

### Headline finding: tuya ipc webrtc is signalled over the tuya mqtt link, not a websocket

Every working third-party implementation of a tuya-platform ip camera exchanges
the webrtc offer/answer/candidates as json messages published over the tuya
mqtt connection, not over an oem's own websocket. Our client already opens the
correct tuya mqtt session (`thing.py`), but uses it only as passive presence:
`mqtt_presence()` subscribes to `<partnerIdentity>/mb/<uid>` and
`smart/mb/in/<deviceId>` and then just yields. Meanwhile the offer still goes
out over `wss.eu.nooie.com/ws` as `service.SdpOffer` (`client.py` ~line 970).
So the media negotiation is happening on a different plane from the one the
camera answers on. That mismatch is consistent with a parsed-but-declined
`Ret=8`.

There are two topic dialects. nooie's app is a thing-sdk 5.7.10 session, so it
uses the **mobile-sdk dialect** (not the web/open-api `/av/moto/...` dialect
that go2rtc/tuya-ipc-terminal use):

```text
publish   smart/mb/out/<devId>          # offer / candidates go here
subscribe smart/mb/in/<devId>           # answer / candidates arrive here
broker    ssl://<login.domain.mobileMqttsUrl>:8883   # our m1.tuyaeu.com:8883
```

we already subscribe to `smart/mb/in/<devId>` for presence — that is the
**answer** channel. we never **publish** the offer to `smart/mb/out/<devId>`;
today the offer leaves over the nooie websocket instead. that is the core bug.

the 302 outer frame is aes-wrapped with `localKey` (16 ascii bytes, aes-128-ecb
/ pkcs5, no iv):

```jsonc
{ "protocol": "302", "pv": "2.2", "t": <unix>, "gwId": "<devId>",
  "data": base64(aes_ecb(localKey, innerJson)) }
```

inner envelope `{header, msg}`:

```jsonc
header: { type:"offer"|"answer"|"candidate"|"disconnect",
          from, to, sessionid, moto_id, trace_id, transaction_id,
          seq, rtx, is_pre, p2p_skill, path:"mqtt"|"lan", sub_dev_id }
offer msg:  { mode:"webrtc", sdp, stream_type, auth, token:[iceServers],
              datachannel_enable, replay:{is_replay:0} }
answer msg: { mode:"webrtc", sdp }
cand msg:   { mode:"webrtc", candidate:"a=candidate:...\r\n" }  // "" = end
```

protocol **312** carries control: `resolution` (`cmdValue` 0=hd/1=sd) and
`speaker` (audio backchannel).

sdp rules that silently break naive offers (all confirmed across working
clients):

- **`auth` is a mandatory admission token in the offer msg** — without it the
  device rejects. it comes from the rtc-config call below, not from us.
- **strip every `a=extmap:` line** — device caps the json payload at ~8 kb.
- **put the audio m-line first**, or tuya returns corrupt sdp.
- h264 rides normal rtp tracks; h265/hevc rides a webrtc **datachannel**
  `fmp4Stream` (MaxRetransmits 5, ordered) after a handshake
  (`{"type":"codec"}` → `{"type":"start","msg":"frame"}` → camera returns
  ssrcs → `{"type":"complete"}`). cameras answer h264 in the sdp even for hevc,
  so codec comes from `skill`, not the answer.

### the single decisive call: `tuya.m.rtc.session.init`

one signed thing request on the api we already talk to
(`a1.tuyaeu.com/api.json`) settles everything:

```text
a=tuya.m.rtc.session.init  v=1.0  postData={"devId":"<devId>"}
```

(it replaces the deprecated `tuya.m.ipc.config.get` v2.0.) the response hands
us **every** webrtc credential we currently lack: `p2pType` (2=cs2/ppcs,
4=thing-webrtc), `p2pId`, `password`, `localKey`, `motoId`, `auth`,
`p2pConfig.ices[]`, and `skill`. it tells us which transport the ipc007 really
speaks, and it has a documented **side-effect**: *"tuya cloud will send an offer
to device, speed up the connection process."* that priming is a concrete,
testable explanation for `Ret=8` — a camera the cloud has primed with its own
offer may refuse an unprimed third-party one. this is the first thing to try
with the thing session `thing.py` already builds.

### working reference implementations (this is a solved problem elsewhere)

- **go2rtc** tuya module — full, current, byte-level description of the flow:
  - https://deepwiki.com/AlexxIT/go2rtc/3.7.2-tuya-cameras
  - https://deepwiki.com/skrashevich/go2rtc/4.6.2-tuya-devices
  it supports both the **consumer app** login (`*.ismartlife.me`, email +
  md5→rsa password, `POST /api/login/token`, `POST /api/private/email/login`,
  `POST /api/jarvis/config`, `POST /api/jarvis/mqtt`) and the **tuya iot cloud**
  login (`GET /v1.0/token`, `GET /v1.0/users/{uid}/devices/{deviceId}/webrtc-configs`,
  `POST /v2.0/open-iot-hub/access/config`).
- **seydx/tuya-ipc-terminal** — cli that streams tuya cameras to rtsp by the
  same reverse-engineered consumer-app apis (regional hosts
  `protect-eu.ismartlife.me`, etc.): https://github.com/seydx/tuya-ipc-terminal
- tuya's own references for the message shapes: `tuya/webrtc-demo-go`,
  `tuya/tuya-rtc-camera-sdk-android`, and the cloud doc
  https://developer.tuya.com/en/docs/cloud/96c3154b0d?id=Kam7q5rz91dml
  ("get configs of creating webrtc connection" → `p2p_config`).

### the tempting sidestep (pair into the generic tuya app) is very likely closed

The obvious "just use go2rtc" idea is to **pair the camera into the generic tuya
"smart life" / ismartlife.me account** and drive it with go2rtc or
tuya-ipc-terminal. after checking the tooling and tuya's own docs, treat this as
**probably blocked**, worth only a 10-minute empirical confirmation:

- **oem apps and smart life are separate ecosystems and the device is
  pid-locked.** nooie is a tuya *oem auto-built app*
  (https://developer.tuya.com/en/docs/iot/appautobuilding?id=K97dki9m38d8w);
  the device is bound to nooie's product id. re-pairing an oem device into smart
  life throws tuya's documented "device has been paired previously using a
  different PID" activation error
  (https://developer.tuya.com/en/docs/iot-device-dev/Distribution-network-problem-Wi-Fi?id=Kaunggovmyubu).
- **the reference tools require a genuine tuya account, not an oem one.**
  go2rtc states outright that **"Smart Life accounts are NOT supported"** (it
  needs a *tuya smart* account with the cam added) — https://go2rtc.org/internal/tuya/ ;
  tuya-ipc-terminal likewise only sees cameras already bound to a tuya
  smart / smart life account and claims no oem-app support.
- community evidence agrees: the osaio HA thread's "add via tuya app then use
  the tuya integration" trick **failed** for every user who tried it (gncc
  P1/T2/XC100/GC3/GC4) — https://community.home-assistant.io/t/osaio-camera-integration/398771 .

so the clean official-tuya toolchain (smart-life binding, iot-core project
linking, `stream/actions/allocate` rtsp/hls, running go2rtc as-is) is unreachable
for this camera. its value to us is as a **reference implementation of the
signalling** (below), not as a runnable shortcut.

### legacy path worth a cheap probe (probably closed on fw 7.x)

Bitdefender's 2022 disclosure documents an **older** nooie transport: the
camera connected to mqtt at `eu.nooie.com:1883` (no auth) and accepted a
`/device/<ID>/cmd` message carrying `{cmd,url}` that told the camera to **push**
its **rtsps** stream to an arbitrary url. this is a completely different
"camera-push" model, not webrtc.
- https://www.bitdefender.com/en-us/blog/labs/vulnerabilities-identified-in-nooie-baby-monitor
- affected fw then: PC100A 1.3.88, IPC007A-1080P 2.1.94. the old nooie cam app
  was retired 2022-02-01 and our camera is on the new tuya stack (fw 7.1.71),
  so this is likely gone — but `eu.nooie.com:1883` and a residual cmd path are
  trivial to probe and would, if alive, give a plain rtsps pull with no webrtc
  at all.

### routes that are dead ends (don't spend time here)

- **local rtsp / onvif**: nooie cameras expose none. confirmed across the ha
  community thread (https://community.home-assistant.io/t/integrate-nooie-cam-360/189977)
  and ipc reverse-engineering forums.
- **firmware mod (thingino / openipc)**: the sensor/soc (ingenic-class) has no
  device support for these nooie/apeman/osaio models; the sibling vicohome
  effort hit the identical wall (soc unsupported, all local ports closed) and
  ended up **cloud-only**
  (https://community.home-assistant.io/t/help-with-reverse-engineering-webrtc-with-vicohome-camera/653221).

### on `Ret=8` specifically — it is nooie's own code, not tuya's

correction to the earlier guess: a search of tuya's docs and every rev-eng
project found **`Ret` is not a field in any tuya 302 schema at all** — tuya
answers are `{mode, sdp}` only. so `Ret=8` originates in osaio/nooie's **own**
protobuf signalling layer (the twofish-over-tcp rpc keyed
`md5(method + transId + "ApEMaNSNoOiE")` that `apeman.py` already implements),
not in the tuya stack. its meaning has to be pulled from a binary — the
`SdpAnswer` enum in the ios app or the camera's `anyka_ipc` binary — not from
the web. this reframes `Ret=8` as a nooie-websocket-plane artefact, which is
further reason to abandon that plane for the tuya-mqtt-302 path above. (context:
https://www.trevorkems.com/operation-big-brother-iot-camera/ )

### legacy plain-tcp a/v on port 16116 (almost free to check)

nooie/victure/apeman (same vendor) historically stream a/v over **unencrypted
tcp on port 16116** — a 16-byte header then raw h264/h265/alaw. there is a
ready wireshark dissector (`victure.lua`) at
https://github.com/TKems/Victure-Camera-Vulnerabilities :

```text
u32 messageSize | u8 syncOne | u8 syncTwo | u8 mediaType | u8 eckByte
u16 seqNum | u16 dataLength | u32 timestamp | raw h264/h265/alaw
mediaType: 5=H265, 2=ALAW
```

an `nmap -p 16116` against the camera and, if open, the dissector on a capture,
is a near-zero-cost check for a raw local stream that bypasses all the cloud
crypto.

### do this first: read the existing pcap

Before writing any code, inspect `nooie-official-login-live.pcap` (and
`apeman.pcap`) for the **live-view trigger**. one look disambiguates the two
transports: if the official app negotiates video via mqtt-302 offer/answer, we
are on the webrtc path (→ recommendation 1); if instead it publishes a
`cmd`+`url` to make the camera push rtsps, the old reverse-push path survives in
fw 7.x (→ recommendation 3, which is then the easiest route of all). we already
have these captures; this is the cheapest, most decisive next action.

### ranked recommendation

1. **call `tuya.m.rtc.session.init` with the thing session `thing.py` already
   builds** — one signed request that both reveals `p2pType` (which transport
   the ipc007 actually speaks) and returns `localKey`/`motoId`/`auth`/`ices` —
   the credentials we currently lack — and primes the camera. decisive, cheap,
   uses machinery we already have.
2. **read `nooie-official-login-live.pcap`** for the app's *successful* live
   view: does an sdp offer ever cross the nooie websocket in cleartext? if not,
   a/v is negotiated inside tls:8883 and the websocket/`service.SdpOffer` plane
   (and its `Ret=8`) is a dead end regardless.
3. **if `p2pType=4`: move signalling onto tuya mqtt-302.** publish the offer to
   `smart/mb/out/<devId>` (aes-ecb framed with `localKey`, `auth` token
   included, extmap stripped, audio m-line first) and read the answer off
   `smart/mb/in/<devId>` — the topic we already subscribe to — instead of
   `service.SdpOffer`. mirror tuya-ipc-terminal's envelope and go2rtc's sdp
   rules; `eisbaw/babymonitor-client` has the mobile-dialect specifics.
4. **near-free local checks in parallel:** `nmap -p 16116` (legacy raw-tcp a/v,
   victure dissector) and probe `eu.nooie.com:1883` for a surviving `cmd/url`
   rtsps-push path.
5. **ruled out — pairing into smart life / official tuya cloud.** oem pid-lock;
   go2rtc/tuya-ipc-terminal need a genuine tuya account. confirm with a 10-min
   smart-life pairing attempt, then drop.
6. abandon local rtsp/onvif/firmware — none exist for this hardware (sibling
   gncc is anyka ak3918, outside thingino/openipc's ingenic-only support).

### key reference repos

- `seydx/tuya-ipc-terminal` — `pkg/tuya/mqttCamera.go`, `pkg/tuya/api.go`.
- `AlexxIT/go2rtc` — `pkg/tuya/{client,smart_api,cloud_api,mqtt}.go`.
- `eisbaw/babymonitor-client` — deepest public tuya-ipc rev-eng, mobile dialect
  (`re/mqtt_signaling.md`, `re/webrtc_session.md`); also the mqtt CONNECT
  credential derivation, which cross-checks our `derive_mqtt_credentials`.
- `azerty9971/xtend_tuya` — python webrtc reference manager.
- `TKems/Victure-Camera-Vulnerabilities` — port-16116 dissector.

## 2026-07-26 — live-login correction and first full integration result

This corrects the earlier implementation checkpoint's unverified password
theory. Thing SDK 5.7.10 does **not** use PKCS#1 v1.5 for this UID-login path,
and supplying a double-MD5 password was also rejected by the live service.
The native path is:

```text
raw Nooie account password
  -> lowercase ASCII MD5 hex digest
  -> raw RSA public operation (`kSecPaddingNone`)
  -> modulus-sized, zero-left-padded ciphertext
  -> lowercase hex in `passwd`
```

That construction matches the successful captured `passwd` byte-for-byte.
The independent client now performs it directly, and a live UID login succeeds
with a newly persisted Thing device identity while the official Nooie app is
not running.

The recovered MQTT credentials also pass a live broker test: TLS connection,
MQTT 3.1.1 CONNACK, QoS 1 subscription to the account mailbox, a short held
presence interval, and clean disconnect all succeeded. The broker rejected
`smart/mb/in/<Nooie camera ID>`; that identifier is not a Thing device ID, so
the bootstrap now subscribes only to the SDK's account mailbox.

The first complete app-absent CLI run therefore reached all of the following:

1. Nooie login and device discovery;
2. independent Thing UID login;
3. authenticated Thing MQTT presence;
4. Nooie P2P registration, signalling WebSocket connection, and SDP offer.

The camera nevertheless returned `response.SdpAnswer Ret=8`, and no recording
was created. This disproves the narrow hypothesis that a Thing login plus the
account-level MQTT subscription alone is sufficient. Current work is tracing
the official post-login bootstrap and the exact MQTT client identity, then
will repeat the full run and test suite.

### MQTT identity trace

The MQTT client identity has now been checked directly in the bundled SDK.
`ThingSmartDeviceCoreEntry`
`configMQTT:appKey:appSecret:ecode:partnerIdentity:uuid:sid:` receives the
result of `ThingSmartSDK.uuid` as its `uuid` argument. This is the same
persistent Thing identifier carried as `deviceId` by signed mobile API
requests, so the independent identity currently supplied to
`derive_mqtt_credentials()` is correct. The remaining `Ret=8` investigation
should not substitute the Nooie `phone_code` or camera ID into the MQTT client
ID.

## 2026-07-26 — exact post-login bootstrap tested; `Ret=8` remains

The official app's remaining ordinary post-login calls have now been recovered
and exercised by the independent client. The Nooie `/v2/user/put` request uses
the same 13-field install metadata shape as the captured iOS request, including
the stable `phone_code`; it completed successfully before device discovery.
The Thing client then made the SDK's signed, encrypted
`m.life.home.space.list` v1.0 request and
`m.life.my.group.device.list` v2.2 request. The live account currently has one
home and zero Thing device entries.

The official MQTT trace contains two equal-size encrypted SUBSCRIBE records.
The independently derived account topic is 32 bytes, which produces that
observed record size; the sole `m/ug/<homeId>` topic is only 14 bytes and would
produce a distinctly shorter record. The duplicate official subscriptions are
therefore the account mailbox registered by two SDK consumers
(`ThingHomeCacheService` and `ThingSmartCallMQTTHandler`), not an omitted home
or camera topic. A single broker subscription has the same server-side effect.

The compact-offer prefix was also corrected back to the proven wire form:
`30 30 0a` (`00` plus bare LF). Only the compact camera answer uses CRLF. This
is backed by the earlier controlled live test in which CRLF offers were
silently dropped while bare-LF offers immediately produced
`response.SdpAnswer`.

A new complete run, with the official Nooie app confirmed absent, successfully
completed all of these steps:

1. Nooie credential login and `/user/put` install registration;
2. camera discovery;
3. independent Thing UID login;
4. Thing home and device-list bootstrap;
5. MQTT 3.1.1 TLS connection and account-mailbox subscription;
6. Nooie NAT registration, signalling connection, session creation, and
   compact SDP offer delivery.

The camera still returned `Ret=8`, and the output directory remained empty.
This rules out the normal Nooie install registration and the complete observed
Thing login/home/MQTT bootstrap as the missing authorization event. The
remaining investigation is confined to Nooie's long-lived native P2P
connection/presence, which is separate from both the HTTP session and Thing
MQTT.

## 2026-07-26 19:20 BST — observable-parity pass and full verification

The “long-lived native P2P presence” hypothesis at the end of the preceding
checkpoint has now been disproved by accounting for every flow in the
successful official capture. There is no separate port-6116 connection during
live-view setup. The official media path is Nooie's clear
`service.SdpOffer`/`response.SdpAnswer` WebSocket exchange followed by direct
WebRTC; the Thing MQTT connection performs two duplicate account-mailbox
subscriptions and no publish.

### Identity and bootstrap controls

The following controlled substitutions and replays all reached the camera but
left its answer at `Ret=8`:

- the captured stable Nooie HTTP request UUID;
- the captured Thing device UUID;
- the exact captured `phone_code` (the configured value was compared without
  printing it);
- all three together, with the captured Thing platform/model, `en-GB` locale,
  OS metadata, and exact Nooie install metadata;
- ten of twelve ordinary read-only UI API calls from the official session (the
  remaining two returned normal endpoint errors);
- the official six-message `atr.get` sequence around candidate delivery.

The Nooie login request and `/user/put` use different captured brand values.
The implementation now preserves that distinction:

```text
login/login phone_brand:  iPad Pro 12.9-in. 3rd gen
user/put phone_brand:     Apple
```

The current Nooie JWT has the same key/type shape and stable claims as the
captured official JWT. Expected per-login token and transaction claims differ.
No identity-field combination changed the camera decision.

### Offer, candidate, and WebSocket parity

After masking only per-session randomness, the generated compact offer has
zero differing keys, types, or static values from a captured `Ret=0` offer.
The wire prefix is the required bare-LF `00\n`; the earlier CRLF experiment
caused silent drops. Across 24 captured official offers, every ICE ufrag has
length four and every password has length 24. The client now preserves
aioice's four-character default and changes only its 22-character password
request to 24.

The two emitted candidates match the official host-then-relay sequence, use
media section zero, and are both acknowledged. SocketRocket's generated HTTPS
`Origin` is now present. Its connection builder also confirms that the native
handshake has no automatic `Accept`, `Accept-Encoding`, or `User-Agent`; those
aiohttp defaults are now suppressed. A live run with that narrower handshake
still returned `Ret=8`.

The camera accepted and answered all six `atr.get` reads with complete state,
but they did not alter the answer. They have therefore been removed from
production rather than burdening every call with disproved priming messages.

The persisted Thing identity is created with mode 0600. A final safety review
also removed an unconditional chmod of its parent directory: a user-supplied
path can no longer restrict permissions on an existing shared parent. A
regression test covers this case.

The official diagnostic log contains six accepted live-view sequences. It also
contains one later `Ret=8` answer at 13:55:58, several minutes after the first
accepted sequence, with no adjacent new offer or immediate retry in the log.
It therefore does not support treating `Ret=8` as a condition the official app
fixes with an automatic retry.

### Final verification

The official Nooie process was confirmed absent before the final live test.
That test completed, in order:

1. Nooie login, exact `/user/put`, and camera discovery;
2. independent Thing UID login;
3. MQTT 3.1.1 TLS connection and QoS 1 account subscription;
4. Thing home/device bootstrap (one home, zero Thing devices);
5. Nooie NAT registration, native-shaped WebSocket connection, session
   creation, offer, host candidate, and relay candidate;
6. acknowledgements for `service.Close`, `service.SdpOffer`, and both
   `service.IceCandidate` messages.

The next message was `response.SdpAnswer Ret=8`. The two-second target
recording was not created, and the output directory was empty.

Deterministic verification after removing the attribute experiment:

```text
uv run python -m unittest discover -v
  Ran 15 tests — OK (Python 3.11)

uv run --isolated --python 3.13 python -m unittest discover -v
  Ran 15 tests — OK

uv run python -m compileall -q nooie_tui tests
uvx ruff check --select E,F nooie_tui/client.py nooie_tui/thing.py tests
uv lock --check
git diff --check
  all passed

uv build --out-dir <temporary directory>
  source distribution and wheel built successfully

uv run --isolated --with <built wheel> nooie-tui --help
  installed wheel entry point ran successfully
```

`nooie-tui --check-config` also passed against the mode-0600 private Thing
material file. A value-only scan found zero occurrences of the private Thing
material or sensitive `.env` values in source, tests, configuration examples,
or documentation.

### Current boundary

There is no known missing HTTP, MQTT, NAT, WebSocket, SDP, candidate, or relay
event before the answer. The remaining discriminator is below that observable
sequence: native transport/client state or fingerprinting, or an opaque
backend/camera admission rule. The next useful experiment must isolate that
boundary, such as sending the recovered sequence through the native
SocketRocket/Network.framework stack or instrumenting the app immediately
before `service.SdpOffer`. Repeating Thing calls, UI reads, SDP tuning, or
generic Tuya RTC signalling would re-test paths already ruled out.
