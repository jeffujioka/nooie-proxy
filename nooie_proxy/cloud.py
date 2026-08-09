"""nooie's cloud rest api: sign in, pick the camera, open a webrtc session."""

import base64
import hashlib
import hmac
import os
import time
import uuid
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any

import aiohttp
from aiortc import RTCIceServer

from .env import country, credentials, identity, log

API_BASE = "https://app.eu.nooie.com/v2"
WS_URL = "wss://wss.eu.nooie.com/ws"
APP_ID = "4adcd2139621b1ef"
APP_SECRET = "9e03f0b14adcd2139621b1ef984b2ac0"
USER_AGENT = "Nooie_IOS_3.7.0"


@dataclass(frozen=True)
class Config:
    """everything a call needs once the account and camera are resolved."""

    api_token: str
    uid: str
    phone_code: str
    request_uuid: str
    device_id: str = ""
    model_id: str = ""


def utc_offset_hours() -> int:
    offset = datetime.now().astimezone().utcoffset()
    return int(offset.total_seconds() // 3600) if offset else 0


def headers(config: Config | None, request_uuid: str = "") -> dict[str, str]:
    """the hmac-signed header set; the account fields appear once logged in."""
    timestamp = str(int(time.time()))
    signed = f"{APP_ID}{timestamp}"
    if config is not None:
        signed += f"{config.uid}{config.api_token}"
        request_uuid = config.request_uuid
    digest = hmac.new(
        APP_SECRET.encode(), signed.encode(), hashlib.sha256
    ).hexdigest()
    common = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
        "appid": APP_ID,
        "uuid": request_uuid,
        "timestamp": timestamp,
        "sign": base64.b64encode(digest.encode()).decode(),
    }
    if config is None:
        return common
    return common | {"uid": config.uid, "api-token": config.api_token}


def login_body(username: str, password: str, phone_code: str) -> dict[str, Any]:
    # the app reports a different phone_brand here than at registration.
    return {
        "account": username,
        "country": country(),
        "password": hashlib.md5(password.encode()).hexdigest(),
        "phone_brand": "iPad Pro 12.9-in. 3rd gen",
        "phone_code": phone_code,
        "zone": utc_offset_hours(),
    }


def registration_body(config: Config) -> dict[str, Any]:
    """the install metadata the app posts straight after a successful login."""
    return {
        "phone_brand": "Apple",
        "zone": utc_offset_hours(),
        "phone_version": "26.5",
        "app_version": "3.7.0",
        "phone_screen": "[1470, 956]",
        "device_type": 2,
        "phone_code": config.phone_code,
        "package_name": "com.nooie.home",
        "language": "en",
        "app_version_code": "11",
        "country": country(),
        "push_type": 3,
        "phone_model": "iPad8,6",
    }


async def request(
    http: aiohttp.ClientSession,
    what: str,
    path: str,
    request_headers: dict[str, str],
    method: str = "POST",
    **kwargs: Any,
) -> Any:
    async with http.request(
        method, f"{API_BASE}{path}", headers=request_headers, **kwargs
    ) as response:
        payload = await response.json(content_type=None)
        status = response.status
    code = payload.get("code") if isinstance(payload, dict) else None
    if status != 200 or code != 1000:
        message = payload.get("msg") if isinstance(payload, dict) else None
        raise RuntimeError(
            f"{what} failed: HTTP {status}, code={code}, msg={message!r}"
        )
    return payload.get("data")


async def authenticate(http: aiohttp.ClientSession) -> Config:
    """sign in and register this install, without settling on a camera."""
    username, password = credentials()
    phone_code = identity()
    request_uuid = uuid.uuid4().hex
    data = await request(
        http,
        "login",
        "/login/login",
        headers(None, request_uuid),
        json=login_body(username, password, phone_code),
    )
    if not isinstance(data, dict):
        raise RuntimeError("login response has no data object")
    config = Config(
        api_token=str(data["api_token"]),
        uid=str(data["uid"]),
        phone_code=phone_code,
        request_uuid=request_uuid,
    )
    await request(
        http,
        "client registration",
        "/user/put",
        headers(config),
        json=registration_body(config),
    )
    return config


async def login(http: aiohttp.ClientSession) -> Config:
    """sign in, register this install, and settle on one camera."""
    config = await authenticate(http)
    camera = await select_camera(http, config)
    log(f"selected camera {camera['type']}")
    return replace(
        config, device_id=str(camera["uuid"]), model_id=str(camera["type"])
    )


async def list_devices(http: aiohttp.ClientSession) -> list[dict[str, Any]]:
    """every camera on the account, for NOOIE_DEVICE_ID to choose among."""
    config = await authenticate(http)
    data = await request(
        http,
        "device list",
        "/device/list",
        headers(config),
        method="GET",
        params={"page": 1, "per_page": 100},
    )
    return [
        item
        for item in (data.get("data", []) if isinstance(data, dict) else [])
        if isinstance(item, dict)
    ]


async def select_camera(
    http: aiohttp.ClientSession, config: Config
) -> dict[str, Any]:
    devices = await list_devices(http)
    wanted = os.environ.get("NOOIE_DEVICE_ID", "")
    cameras = [
        item
        for item in devices
        if isinstance(item, dict)
        and item.get("uuid")
        and item.get("type")
        and wanted in ("", item.get("uuid"))
    ]
    online = [item for item in cameras if int(item.get("online", 0)) == 1]
    for group in (online, cameras):
        if len(group) == 1:
            return group[0]
    if not cameras:
        raise RuntimeError("no matching Nooie camera on this account")
    raise RuntimeError("several cameras match; set NOOIE_DEVICE_ID")


async def create_session(
    http: aiohttp.ClientSession, config: Config
) -> dict[str, Any]:
    return await request(
        http,
        "session request",
        "/webrtcsession/user/videocall",
        headers(config),
        json={"device_id": config.device_id},
    )


def ice_servers(session: dict[str, Any]) -> list[RTCIceServer]:
    return [
        RTCIceServer(
            urls=item["iceurl"],
            username=item.get("username") or None,
            credential=item.get("password") or None,
        )
        for item in session.get("user_ices", [])
        if item.get("iceurl")
    ]
