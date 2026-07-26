"""Independent Thing/Tuya UID login and MQTT presence for Nooie."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import locale
import os
import platform
import re
import ssl
import sys
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, AsyncIterator, Callable, Mapping

import aiohttp
import aiomqtt
from aiomqtt import ProtocolVersion
from cryptography.hazmat.primitives import padding as symmetric_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SIGNED_FIELDS = frozenset(
    {
        "a",
        "v",
        "lat",
        "lon",
        "et",
        "lang",
        "deviceId",
        "imei",
        "imsi",
        "appVersion",
        "ttid",
        "isH5",
        "h5Token",
        "os",
        "clientId",
        "postData",
        "time",
        "n4h5",
        "sid",
        "sp",
        "requestId",
    }
)

UUID_PATTERN = re.compile(
    r"^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-"
    r"[0-9A-F]{4}-[0-9A-F]{12}$"
)


class ThingError(RuntimeError):
    """A redaction-safe Thing protocol error."""


@dataclass(frozen=True)
class ThingApp:
    """Shared SDK material extracted from an app bundle owned by the user."""

    app_key: str
    app_secret: str
    secret_pic_key: str
    bundle_id: str = "com.nooie.home"
    api_url: str = "https://a1.tuyaeu.com/api.json"

    @property
    def key_material(self) -> str:
        return (
            f"{self.bundle_id}_{self.secret_pic_key}_{self.app_secret}"
        )


@dataclass(frozen=True)
class ThingRequestProfile:
    """Non-secret SDK metadata carried by each mobile API request."""

    sdk_version: str = "5.7.10"
    device_core_version: str = "5.18.0"
    app_version: str = "3.7.0"
    app_rn_version: str = "5.92"
    channel: str = "sdk"
    ttid: str = "appstore_r"
    os_name: str = "IOS"
    et: str = "0.0.2"
    platform_name: str = field(
        default_factory=lambda: os.environ.get(
            "NOOIE_THING_PLATFORM", platform.machine() or "unknown"
        )
    )
    os_system: str = field(
        default_factory=lambda: os.environ.get(
            "NOOIE_THING_OS_VERSION",
            platform.mac_ver()[0] or platform.release(),
        )
    )
    language: str = field(default_factory=lambda: local_language())
    time_zone_id: str = field(default_factory=lambda: local_time_zone_id())

    @property
    def biz_data(self) -> str:
        return json.dumps(
            {
                "miniappVersion": json.dumps(
                    {
                        "MapKit": "3.9.4",
                        "BizKit": "4.14.8",
                        "BaseKit": "3.18.6",
                        "container": "3.25.0",
                        "MiniKit": "3.15.3",
                        "DeviceKit": "4.13.6",
                        "basicLib": "",
                    },
                    separators=(",", ":"),
                ),
                "nd": 1,
                "customDomainSupport": "1",
            },
            separators=(",", ":"),
        )


@dataclass(frozen=True)
class ThingSession:
    """The minimum successful UID-login result needed for MQTT."""

    sid: str
    ecode: str
    uid: str
    username: str
    partner_identity: str
    domain: Mapping[str, Any]

    @classmethod
    def from_result(cls, result: Mapping[str, Any]) -> ThingSession:
        domain = result.get("domain")
        if not isinstance(domain, dict):
            raise ThingError("Thing login returned no domain configuration")
        values = {
            name: str(result.get(name, ""))
            for name in (
                "sid",
                "ecode",
                "uid",
                "username",
                "partnerIdentity",
            )
        }
        missing = [name for name, value in values.items() if not value]
        if missing:
            raise ThingError(
                "Thing login omitted required fields: " + ", ".join(missing)
            )
        return cls(
            sid=values["sid"],
            ecode=values["ecode"],
            uid=values["uid"],
            username=values["username"],
            partner_identity=values["partnerIdentity"],
            domain=domain,
        )

    @property
    def mqtt_host(self) -> str:
        value = str(self.domain.get("mobileMqttsUrl", ""))
        value = re.sub(r"^[a-z]+://", "", value, flags=re.IGNORECASE)
        value = value.rstrip("/")
        if not value or "/" in value:
            raise ThingError("Thing login returned an invalid MQTT host")
        return value

    @property
    def mqtt_port(self) -> int:
        try:
            value = int(self.domain.get("mqttsPort", 8883))
        except (TypeError, ValueError) as error:
            raise ThingError(
                "Thing login returned an invalid MQTT port"
            ) from error
        if not 1 <= value <= 65535:
            raise ThingError("Thing login returned an invalid MQTT port")
        return value


@dataclass(frozen=True)
class ThingMqttCredentials:
    client_id: str = field(repr=False)
    username: str = field(repr=False)
    password: str = field(repr=False)

    def __repr__(self) -> str:
        return (
            "ThingMqttCredentials("
            f"client_id=<redacted len={len(self.client_id)}>, "
            f"username=<redacted len={len(self.username)}>, "
            f"password=<redacted len={len(self.password)}>)"
        )


def local_language() -> str:
    configured = os.environ.get("NOOIE_THING_LANGUAGE", "")
    if configured:
        return configured
    language = locale.getlocale()[0] or os.environ.get("LANG", "")
    language = language.split(".", 1)[0].replace("_", "-")
    if re.fullmatch(r"[A-Za-z]{2,3}(?:-[A-Za-z]{2})?", language):
        return language
    return "en"


def local_time_zone_id() -> str:
    configured = os.environ.get("NOOIE_THING_TIME_ZONE_ID", "")
    if configured:
        return configured
    zone = getattr(__import__("datetime").datetime.now().astimezone().tzinfo, "key", "")
    if zone:
        return str(zone)
    try:
        resolved = Path("/etc/localtime").resolve()
        marker = "zoneinfo/"
        if marker in str(resolved):
            return str(resolved).split(marker, 1)[1]
    except OSError:
        pass
    return "UTC"


def thing_app_from_environment() -> ThingApp:
    """Load Thing material from individual variables or a private JSON file."""
    material_file = os.environ.get("NOOIE_THING_MATERIAL_FILE", "")
    material: dict[str, Any] = {}
    if material_file:
        path = Path(material_file).expanduser()
        try:
            mode = path.stat().st_mode & 0o777
            if mode & 0o077:
                raise SystemExit(
                    f"{path} contains shared credentials but has mode "
                    f"{mode:04o}; use chmod 600"
                )
            loaded = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as error:
            raise SystemExit(f"cannot read {path}: {error}") from error
        if not isinstance(loaded, dict):
            raise SystemExit(f"{path} must contain a JSON object")
        material = loaded

    app_key = os.environ.get(
        "NOOIE_THING_APP_KEY", str(material.get("app_key", ""))
    )
    app_secret = os.environ.get(
        "NOOIE_THING_APP_SECRET", str(material.get("app_secret", ""))
    )
    secret_pic_key = os.environ.get(
        "NOOIE_THING_SECRET_PIC_KEY",
        str(
            material.get(
                "secret_pic_key", material.get("bmp_key", "")
            )
        ),
    )
    bundle_id = os.environ.get(
        "NOOIE_THING_BUNDLE_ID",
        str(material.get("bundle_id", "com.nooie.home")),
    )
    api_url = os.environ.get(
        "NOOIE_THING_API_URL", "https://a1.tuyaeu.com/api.json"
    )
    values = {
        "app_key": app_key,
        "app_secret": app_secret,
        "secret_pic_key": secret_pic_key,
        "bundle_id": bundle_id,
    }
    missing = [name for name, value in values.items() if not value]
    if missing:
        raise SystemExit(
            "missing Thing configuration: "
            + ", ".join(missing)
            + " (set NOOIE_THING_* or NOOIE_THING_MATERIAL_FILE)"
        )
    if not api_url.startswith("https://"):
        raise SystemExit("NOOIE_THING_API_URL must use HTTPS")
    return ThingApp(
        app_key=app_key,
        app_secret=app_secret,
        secret_pic_key=secret_pic_key,
        bundle_id=bundle_id,
        api_url=api_url,
    )


def default_identity_path() -> Path:
    configured = os.environ.get("NOOIE_THING_IDENTITY_FILE", "")
    if configured:
        return Path(configured).expanduser()
    if sys.platform == "darwin":
        return (
            Path.home()
            / "Library"
            / "Application Support"
            / "nooie-tui"
            / "thing-identity.json"
        )
    state_root = Path(
        os.environ.get(
            "XDG_STATE_HOME", str(Path.home() / ".local" / "state")
        )
    )
    return state_root / "nooie-tui" / "thing-identity.json"


def normalize_device_id(value: str) -> str:
    try:
        normalized = str(uuid.UUID(value)).upper()
    except (ValueError, AttributeError) as error:
        raise ThingError("Thing device identity is not a UUID") from error
    if not UUID_PATTERN.fullmatch(normalized):
        raise ThingError("Thing device identity is not a canonical UUID")
    return normalized


def load_or_create_device_id(path: Path | None = None) -> str:
    configured = os.environ.get("NOOIE_THING_DEVICE_ID", "")
    if configured:
        return normalize_device_id(configured)
    identity_path = path or default_identity_path()
    try:
        value = json.loads(identity_path.read_text())
        if not isinstance(value, dict):
            raise ThingError("Thing identity file is not a JSON object")
        return normalize_device_id(str(value.get("device_id", "")))
    except FileNotFoundError:
        pass
    except (OSError, json.JSONDecodeError) as error:
        raise ThingError(
            f"cannot read Thing identity file {identity_path}"
        ) from error

    identity_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    device_id = str(uuid.uuid4()).upper()
    encoded = (
        json.dumps(
            {"version": 1, "device_id": device_id},
            separators=(",", ":"),
        )
        + "\n"
    ).encode()
    try:
        descriptor = os.open(
            identity_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
    except FileExistsError:
        return load_or_create_device_id(identity_path)
    try:
        os.write(descriptor, encoded)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return device_id


def request_key(app: ThingApp, request_id: str, ecode: str = "") -> bytes:
    material = app.key_material
    if ecode:
        material += f"_{ecode}"
    return hmac.new(
        request_id.encode(),
        material.encode(),
        hashlib.sha256,
    ).hexdigest()[:16].encode()


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
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(
        algorithms.AES(request_key(app, request_id, ecode)),
        modes.ECB(),
    ).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode()


def decrypt_result(
    app: ThingApp,
    request_id: str,
    value: str,
    ecode: str = "",
) -> dict[str, Any]:
    try:
        ciphertext = base64.b64decode(value, validate=True)
        decryptor = Cipher(
            algorithms.AES(request_key(app, request_id, ecode)),
            modes.ECB(),
        ).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = symmetric_padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded) + unpadder.finalize()
        result = json.loads(plaintext)
    except Exception as error:
        raise ThingError("Thing response decryption failed") from error
    if not isinstance(result, dict):
        raise ThingError("Thing response plaintext is not an object")
    return result


def transformed_post_hash(post_data: str) -> str:
    digest = hashlib.md5(post_data.encode()).hexdigest()
    return digest[8:16] + digest[0:8] + digest[24:32] + digest[16:24]


def signing_feed(params: Mapping[str, str]) -> str:
    return "||".join(
        f"{key}="
        f"{transformed_post_hash(value) if key == 'postData' else value}"
        for key, value in sorted(params.items())
        if key in SIGNED_FIELDS and value != ""
    )


def sign_request(app: ThingApp, params: Mapping[str, str]) -> str:
    return hmac.new(
        app.key_material.encode(),
        signing_feed(params).encode(),
        hashlib.sha256,
    ).hexdigest()


def build_request_params(
    app: ThingApp,
    device_id: str,
    profile: ThingRequestProfile,
    action: str,
    version: str,
    post_data: str | None,
    *,
    request_id: str | None = None,
    timestamp: int | None = None,
    sid: str = "",
) -> dict[str, str]:
    request_id = request_id or str(uuid.uuid4()).upper()
    params = {
        "a": action,
        "v": version,
        "time": str(int(time.time()) if timestamp is None else timestamp),
        "requestId": request_id,
        "clientId": app.app_key,
        "deviceId": normalize_device_id(device_id),
        "sdkVersion": profile.sdk_version,
        "deviceCoreVersion": profile.device_core_version,
        "appVersion": profile.app_version,
        "appRnVersion": profile.app_rn_version,
        "bundleId": app.bundle_id,
        "channel": profile.channel,
        "os": profile.os_name,
        "osSystem": profile.os_system,
        "platform": profile.platform_name,
        "lang": profile.language,
        "timeZoneId": profile.time_zone_id,
        "ttid": profile.ttid,
        "et": profile.et,
        "nd": "1",
        "cp": "gzip",
        "lat": "0",
        "lon": "0",
        "bizData": profile.biz_data,
    }
    if post_data is not None:
        params["postData"] = post_data
    if sid:
        params["sid"] = sid
    params["sign"] = sign_request(app, params)
    return params


def rsa_encrypt_password(password: str, public_key_base64: str) -> str:
    try:
        key = serialization.load_der_public_key(
            base64.b64decode(public_key_base64, validate=True)
        )
    except Exception as error:
        raise ThingError("Thing login returned an invalid RSA key") from error
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 1024:
        raise ThingError("Thing login returned an unsupported RSA key")
    digest = hashlib.md5(password.encode()).hexdigest().encode()
    # Thing SDK 5.7.10 explicitly selects kSecPaddingNone here. SecKeyEncrypt
    # treats the short digest as a big-endian integer, equivalent to
    # left-padding it with zero bytes to the RSA modulus size.
    numbers = key.public_numbers()
    message = int.from_bytes(digest, "big")
    if message >= numbers.n:
        raise ThingError("Thing password digest does not fit the RSA key")
    block_size = (key.key_size + 7) // 8
    ciphertext = pow(message, numbers.e, numbers.n)
    return ciphertext.to_bytes(block_size, "big").hex()


class ThingClient:
    def __init__(
        self,
        app: ThingApp,
        device_id: str,
        profile: ThingRequestProfile | None = None,
        *,
        request_id_factory: Callable[[], str] | None = None,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self.app = app
        self.device_id = normalize_device_id(device_id)
        self.profile = profile or ThingRequestProfile()
        self._request_id_factory = request_id_factory or (
            lambda: str(uuid.uuid4()).upper()
        )
        self._clock = clock or (lambda: int(time.time()))

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
        request_id = normalize_device_id(self._request_id_factory())
        post_data = (
            encrypt_post_data(self.app, request_id, payload, ecode)
            if payload is not None
            else None
        )
        params = build_request_params(
            self.app,
            self.device_id,
            self.profile,
            action,
            version,
            post_data,
            request_id=request_id,
            timestamp=self._clock(),
            sid=sid,
        )
        headers = {
            "Accept": "*/*",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": os.environ.get(
                "NOOIE_THING_USER_AGENT", "Nooie_IOS_3.7.0"
            ),
            "x-client-trace-id": request_id,
        }
        try:
            async with http.post(
                self.app.api_url, headers=headers, data=params
            ) as response:
                outer = await response.json(content_type=None)
        except (aiohttp.ClientError, json.JSONDecodeError) as error:
            raise ThingError(f"Thing request {action} failed") from error
        if response.status != 200 or not isinstance(outer, dict):
            raise ThingError(
                f"Thing request {action} failed with HTTP "
                f"{response.status}"
            )
        encrypted = outer.get("result")
        if not isinstance(encrypted, str):
            code = outer.get("errorCode", outer.get("code", "unknown"))
            raise ThingError(
                f"Thing request {action} failed with code {code!r}"
            )
        wrapper = decrypt_result(
            self.app, request_id, encrypted, ecode
        )
        if wrapper.get("success") is not True:
            code = wrapper.get(
                "errorCode", wrapper.get("code", wrapper.get("status"))
            )
            raise ThingError(
                f"Thing request {action} failed with code {code!r}"
            )
        result = wrapper.get("result")
        if result is None:
            raise ThingError(
                f"Thing request {action} returned no result"
            )
        return result

    async def login_by_uid(
        self,
        http: aiohttp.ClientSession,
        uid: str,
        password: str,
        country_code: str,
    ) -> ThingSession:
        token_result = await self.request(
            http,
            "smartlife.m.user.uid.token.create",
            "1.0",
            {"uid": uid, "countryCode": country_code},
        )
        if not isinstance(token_result, dict):
            raise ThingError("Thing token creation returned an invalid result")
        public_key = token_result.get("pbKey")
        token = token_result.get("token")
        if not isinstance(public_key, str) or not isinstance(token, str):
            raise ThingError("Thing token creation returned an invalid result")
        encrypted_password = rsa_encrypt_password(password, public_key)
        login_result = await self.request(
            http,
            "smartlife.m.user.uid.password.login",
            "1.0",
            {
                "countryCode": country_code,
                "passwd": encrypted_password,
                "options": {"group": 1},
                "uid": uid,
                "ifencrypt": 1,
                "token": token,
            },
        )
        if not isinstance(login_result, dict):
            raise ThingError("Thing login returned an invalid result")
        return ThingSession.from_result(login_result)

    async def home_spaces(
        self,
        http: aiohttp.ClientSession,
        session: ThingSession,
    ) -> list[Mapping[str, Any]]:
        """Load the same home-space list requested by the SDK after login."""
        result = await self.request(
            http,
            "m.life.home.space.list",
            "1.0",
            None,
            ecode=session.ecode,
            sid=session.sid,
        )
        if not isinstance(result, list) or not all(
            isinstance(item, dict) for item in result
        ):
            raise ThingError("Thing home-space list returned an invalid result")
        return result

    async def home_devices(
        self,
        http: aiohttp.ClientSession,
        session: ThingSession,
        home_id: int,
    ) -> Any:
        """Load the SDK's home device list for subscription discovery."""
        return await self.request(
            http,
            "m.life.my.group.device.list",
            "2.2",
            {"gid": home_id},
            ecode=session.ecode,
            sid=session.sid,
        )


def md5_hex(value: str) -> str:
    return hashlib.md5(value.encode()).hexdigest()


def derive_mqtt_credentials(
    app: ThingApp,
    session: ThingSession,
    terminal_id: str,
) -> ThingMqttCredentials:
    """Reproduce ThingSmartCore's SDK 5.7.10 legacy MQTT credentials."""
    terminal_id = normalize_device_id(terminal_id)
    client_hash = md5_hex(session.sid + "sdkfasodifca")
    client_id = f"iOS_{terminal_id}_{client_hash}"

    username_tail = md5_hex(md5_hex(app.app_key) + session.ecode)[16:32]
    username = (
        f"{session.partner_identity}_{app.app_key}_mb_"
        f"{session.sid}{username_tail}"
    )

    password_hash = md5_hex(md5_hex(app.key_material) + session.ecode)
    password = password_hash[8:24]
    return ThingMqttCredentials(
        client_id=client_id,
        username=username,
        password=password,
    )


def mqtt_topics(session: ThingSession) -> list[str]:
    # Nooie camera IDs are not Thing device IDs. The SDK's login bootstrap
    # subscribes the account mailbox; smart/mb/in/<deviceId> is reserved for
    # actual Thing device entries and the broker rejects a Nooie camera ID.
    return [f"{session.partner_identity}/mb/{session.uid}"]


def _subscription_failed(reason_codes: Any) -> bool:
    if reason_codes is None:
        return False
    values = (
        list(reason_codes)
        if isinstance(reason_codes, (list, tuple))
        else [reason_codes]
    )
    for value in values:
        if getattr(value, "is_failure", False):
            return True
        try:
            if int(value) == 0x80:
                return True
        except (TypeError, ValueError):
            pass
    return False


@asynccontextmanager
async def mqtt_presence(
    app: ThingApp,
    session: ThingSession,
    terminal_id: str,
) -> AsyncIterator[None]:
    credentials = derive_mqtt_credentials(app, session, terminal_id)
    tls_context = ssl.create_default_context()
    client = aiomqtt.Client(
        hostname=session.mqtt_host,
        port=session.mqtt_port,
        username=credentials.username,
        password=credentials.password,
        identifier=credentials.client_id,
        protocol=ProtocolVersion.V311,
        clean_session=True,
        keepalive=60,
        tls_context=tls_context,
        timeout=15,
        max_queued_incoming_messages=100,
    )
    try:
        async with client:
            print(
                f"connected to Thing MQTT at "
                f"{session.mqtt_host}:{session.mqtt_port}",
                flush=True,
            )
            topics = mqtt_topics(session)
            for topic in topics:
                result = await client.subscribe(topic, qos=1)
                if _subscription_failed(result):
                    raise ThingError(
                        "Thing MQTT broker rejected a required subscription"
                    )
            print(
                f"Thing MQTT subscribed to {len(topics)} required "
                f"topic{'s' if len(topics) != 1 else ''}",
                flush=True,
            )
            yield
    except aiomqtt.MqttError as error:
        raise ThingError("Thing MQTT bootstrap failed") from error
