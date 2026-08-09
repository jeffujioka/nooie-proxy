"""nooie-proxy: sign in to a nooie camera and put its stream on stdout."""

import asyncio
import sys

import aiohttp

from . import apeman, cloud, thing
from .env import load_environment, log, output
from .stream import stream


async def serve() -> None:
    target = output()
    async with aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=30)
    ) as http:
        config = await cloud.login(http)
        async with thing.presence(http, config.uid):
            # publish our nat mapping on nooie's p2p network so the camera
            # can reach us; the registration holds its udp socket open.
            registration = await asyncio.to_thread(apeman.register, config.uid)
            log(f"p2p registered from {registration.wan_ip}")
            await stream(config, target)


async def list_devices() -> None:
    """print every camera on the account so NOOIE_DEVICE_ID can be chosen."""
    async with aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=30)
    ) as http:
        devices = await cloud.list_devices(http)
    print("\t".join(("uuid", "name", "model", "online")))
    for device in devices:
        print(
            "\t".join(
                (
                    str(device.get("uuid", "")),
                    str(device.get("name", "")),
                    str(device.get("type", "")),
                    "yes" if int(device.get("online", 0)) == 1 else "no",
                )
            )
        )


def main(argv: list[str] | None = None) -> None:
    argv = sys.argv[1:] if argv is None else argv
    load_environment()
    if "--list-devices" in argv:
        asyncio.run(list_devices())
    else:
        asyncio.run(serve())
