"""the thing/tuya account layer nooie bundles alongside its own.

a nooie login alone is not enough: the camera only accepts calls while the
account is present on thing's mqtt broker, so this signs in by uid, walks the
same home bootstrap the sdk does, and holds the mqtt session open.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import ssl
import time
import uuid
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

import aiohttp
import aiomqtt
from aiomqtt import ProtocolVersion
from cryptography.hazmat.primitives import padding as symmetric_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .env import canonical_uuid, country, credentials, identity, log
from .profile import (
    THING_API_URL,
    THING_APP_KEY,
    THING_APP_SECRET,
    THING_BUNDLE_ID,
    THING_PICTURE_KEY,
    THING_SDK,
    USER_AGENT,
)

# the parameters the sdk feeds into the request signature; everything else it
# sends is metadata the server echoes back unverified.
SIGNED_FIELDS = frozenset(
    "a v lat lon et lang deviceId imei imsi appVersion ttid isH5 h5Token os "
    "clientId postData time n4h5 sid sp requestId".split()
)


class ThingError(RuntimeError):
    """a redaction-safe thing protocol error."""


@dataclass(frozen=True)
class ThingApp:
    """the credentials nooie ships inside its app bundle."""

    app_key: str = THING_APP_KEY
    app_secret: str = THING_APP_SECRET
    secret_pic_key: str = THING_PICTURE_KEY
    bundle_id: str = THING_BUNDLE_ID

    @property
    def key_material(self) -> str:
        return f"{self.bundle_id}_{self.secret_pic_key}_{self.app_secret}"


@dataclass(frozen=True)
class ThingSession:
    """the minimum successful uid-login result needed for mqtt."""

    sid: str
    ecode: str
    uid: str
    partner_identity: str
    domain: Mapping[str, Any]

    def __repr__(self) -> str:
        # sid and ecode are session secrets; keep them out of tracebacks.
        return "ThingSession(<redacted>)"

    @classmethod
    def from_result(cls, result: Mapping[str, Any]) -> ThingSession:
        if not isinstance(result.get("domain"), dict):
            raise ThingError("Thing login returned no domain configuration")
        names = ("sid", "ecode", "uid", "partnerIdentity")
        values = {name: str(result.get(name, "")) for name in names}
        missing = [name for name, value in values.items() if not value]
        if missing:
            raise ThingError(
                "Thing login omitted required fields: " + ", ".join(missing)
            )
        return cls(
            sid=values["sid"],
            ecode=values["ecode"],
            uid=values["uid"],
            partner_identity=values["partnerIdentity"],
            domain=result["domain"],
        )

    @property
    def mqtt_endpoint(self) -> tuple[str, int]:
        host = str(self.domain.get("mobileMqttsUrl", "")).partition("://")
        host = (host[2] or host[0]).strip("/")
        try:
            port = int(self.domain.get("mqttsPort", 8883))
        except (TypeError, ValueError) as error:
            raise ThingError("Thing login gave an invalid MQTT port") from error
        if not host or "/" in host or not 1 <= port <= 65535:
            raise ThingError("Thing login gave an invalid MQTT endpoint")
        return host, port


@dataclass(frozen=True)
class MqttCredentials:
    client_id: str
    username: str
    password: str

    def __repr__(self) -> str:
        return "MqttCredentials(<redacted>)"


def md5_hex(value: str) -> str:
    return hashlib.md5(value.encode()).hexdigest()


def request_key(app: ThingApp, request_id: str, ecode: str = "") -> bytes:
    material = app.key_material + (f"_{ecode}" if ecode else "")
    return (
        hmac.new(request_id.encode(), material.encode(), hashlib.sha256)
        .hexdigest()[:16]
        .encode()
    )


def encrypt_post_data(
    app: ThingApp,
    request_id: str,
    payload: Mapping[str, Any],
    ecode: str = "",
) -> str:
    plaintext = json.dumps(
        payload, ensure_ascii=False, separators=(",", ":")
    ).encode()
    padder = symmetric_padding.PKCS7(128).padder()
    encryptor = Cipher(
        algorithms.AES(request_key(app, request_id, ecode)), modes.ECB()
    ).encryptor()
    padded = padder.update(plaintext) + padder.finalize()
    return base64.b64encode(
        encryptor.update(padded) + encryptor.finalize()
    ).decode()


def decrypt_result(
    app: ThingApp, request_id: str, value: str, ecode: str = ""
) -> dict[str, Any]:
    try:
        decryptor = Cipher(
            algorithms.AES(request_key(app, request_id, ecode)), modes.ECB()
        ).decryptor()
        padded = (
            decryptor.update(base64.b64decode(value, validate=True))
            + decryptor.finalize()
        )
        unpadder = symmetric_padding.PKCS7(128).unpadder()
        result = json.loads(unpadder.update(padded) + unpadder.finalize())
    except Exception as error:
        raise ThingError("Thing response decryption failed") from error
    if not isinstance(result, dict):
        raise ThingError("Thing response plaintext is not an object")
    return result


def sign_request(app: ThingApp, params: Mapping[str, str]) -> str:
    def signed_value(key: str, raw: str) -> str:
        if key != "postData":
            return raw
        # the post body is folded in as a shuffled md5 of itself.
        digest = md5_hex(raw)
        return digest[8:16] + digest[:8] + digest[24:32] + digest[16:24]

    feed = "||".join(
        f"{key}={signed_value(key, raw)}"
        for key, raw in sorted(params.items())
        if key in SIGNED_FIELDS and raw != ""
    )
    return hmac.new(
        app.key_material.encode(), feed.encode(), hashlib.sha256
    ).hexdigest()


def build_request_params(
    app: ThingApp,
    device_id: str,
    action: str,
    version: str,
    post_data: str | None,
    *,
    request_id: str,
    timestamp: int,
    sid: str = "",
) -> dict[str, str]:
    params = THING_SDK | {
        "a": action,
        "v": version,
        "time": str(timestamp),
        "requestId": request_id,
        "clientId": app.app_key,
        "deviceId": canonical_uuid(device_id),
        "bundleId": app.bundle_id,
    }
    if post_data is not None:
        params["postData"] = post_data
    if sid:
        params["sid"] = sid
    return params | {"sign": sign_request(app, params)}


def rsa_encrypt_password(password: str, public_key_base64: str) -> str:
    try:
        key = serialization.load_der_public_key(
            base64.b64decode(public_key_base64, validate=True)
        )
    except Exception as error:
        raise ThingError("Thing login returned an invalid RSA key") from error
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 1024:
        raise ThingError("Thing login returned an unsupported RSA key")
    # sdk 5.7.10 asks for kSecPaddingNone, so the md5 digest is enciphered as a
    # bare big-endian integer: zero-padded to the modulus, no pkcs#1 envelope.
    numbers = key.public_numbers()
    message = int.from_bytes(md5_hex(password).encode(), "big")
    if message >= numbers.n:
        raise ThingError("Thing password digest does not fit the RSA key")
    block = pow(message, numbers.e, numbers.n)
    return block.to_bytes((key.key_size + 7) // 8, "big").hex()


def derive_mqtt_credentials(
    app: ThingApp, session: ThingSession, terminal_id: str
) -> MqttCredentials:
    """reproduce thingsmartcore's sdk 5.7.10 legacy mqtt credentials."""
    tail = md5_hex(md5_hex(app.app_key) + session.ecode)[16:32]
    return MqttCredentials(
        client_id=(
            f"iOS_{canonical_uuid(terminal_id)}_"
            f"{md5_hex(session.sid + 'sdkfasodifca')}"
        ),
        username=(
            f"{session.partner_identity}_{app.app_key}_mb_{session.sid}{tail}"
        ),
        password=md5_hex(md5_hex(app.key_material) + session.ecode)[8:24],
    )


def mqtt_topic(session: ThingSession) -> str:
    # nooie camera ids are not thing device ids, so only the account mailbox
    # is subscribable here; smart/mb/in/<deviceId> is rejected by the broker.
    return f"{session.partner_identity}/mb/{session.uid}"


class ThingClient:
    def __init__(self, app: ThingApp, device_id: str) -> None:
        self.app = app
        self.device_id = canonical_uuid(device_id)

    async def request(
        self,
        http: aiohttp.ClientSession,
        action: str,
        version: str,
        payload: Mapping[str, Any] | None,
        *,
        ecode: str = "",
        sid: str = "",
    ) -> Any:
        request_id = str(uuid.uuid4()).upper()
        params = build_request_params(
            self.app,
            self.device_id,
            action,
            version,
            None
            if payload is None
            else encrypt_post_data(self.app, request_id, payload, ecode),
            request_id=request_id,
            timestamp=int(time.time()),
            sid=sid,
        )
        try:
            async with http.post(
                THING_API_URL,
                headers={
                    "Accept": "*/*",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": USER_AGENT,
                    "x-client-trace-id": request_id,
                },
                data=params,
            ) as response:
                outer = await response.json(content_type=None)
                status = response.status
        except (aiohttp.ClientError, json.JSONDecodeError) as error:
            raise ThingError(f"Thing request {action} failed") from error
        if status != 200 or not isinstance(outer, dict):
            raise ThingError(f"Thing request {action} failed: HTTP {status}")
        if not isinstance(outer.get("result"), str):
            raise ThingError(
                f"Thing request {action} failed with code "
                f"{outer.get('errorCode', outer.get('code'))!r}"
            )
        wrapper = decrypt_result(self.app, request_id, outer["result"], ecode)
        if wrapper.get("success") is not True or wrapper.get("result") is None:
            raise ThingError(
                f"Thing request {action} failed with code "
                f"{wrapper.get('errorCode', wrapper.get('code'))!r}"
            )
        return wrapper["result"]

    async def login_by_uid(
        self, http: aiohttp.ClientSession, uid: str, password: str
    ) -> ThingSession:
        token = await self.request(
            http,
            "smartlife.m.user.uid.token.create",
            "1.0",
            {"uid": uid, "countryCode": country()},
        )
        if not isinstance(token, dict) or not isinstance(
            token.get("pbKey"), str
        ):
            raise ThingError("Thing token creation returned an invalid result")
        login = await self.request(
            http,
            "smartlife.m.user.uid.password.login",
            "1.0",
            {
                "countryCode": country(),
                "passwd": rsa_encrypt_password(password, token["pbKey"]),
                "options": {"group": 1},
                "uid": uid,
                "ifencrypt": 1,
                "token": token["token"],
            },
        )
        if not isinstance(login, dict):
            raise ThingError("Thing login returned an invalid result")
        return ThingSession.from_result(login)

    async def bootstrap_homes(
        self, http: aiohttp.ClientSession, session: ThingSession
    ) -> None:
        """walk the home lists the sdk loads before it considers itself up."""
        homes = await self.request(
            http,
            "m.life.home.space.list",
            "1.0",
            None,
            ecode=session.ecode,
            sid=session.sid,
        )
        for home in homes if isinstance(homes, list) else []:
            try:
                home_id = int(home.get("gid", home.get("groupId")))
            except (AttributeError, TypeError, ValueError):
                continue
            await self.request(
                http,
                "m.life.my.group.device.list",
                "2.2",
                {"gid": home_id},
                ecode=session.ecode,
                sid=session.sid,
            )


@asynccontextmanager
async def presence(
    http: aiohttp.ClientSession, uid: str
) -> AsyncIterator[None]:
    """hold the account present on thing's broker for the life of the block."""
    app = ThingApp()
    terminal_id = identity()
    client = ThingClient(app, terminal_id)
    session = await client.login_by_uid(http, uid, credentials()[1])
    credential = derive_mqtt_credentials(app, session, terminal_id)
    host, port = session.mqtt_endpoint
    try:
        # the sdk opens mqtt straight after login, then finishes its home
        # bootstrap on the still-live https session.
        async with aiomqtt.Client(
            hostname=host,
            port=port,
            username=credential.username,
            password=credential.password,
            identifier=credential.client_id,
            protocol=ProtocolVersion.V311,
            clean_session=True,
            keepalive=60,
            tls_context=ssl.create_default_context(),
            timeout=15,
            max_queued_incoming_messages=100,
        ) as mqtt:
            await mqtt.subscribe(mqtt_topic(session), qos=1)
            await client.bootstrap_homes(http, session)
            log("present on Thing")
            yield
    except aiomqtt.MqttError as error:
        raise ThingError("Thing MQTT bootstrap failed") from error
