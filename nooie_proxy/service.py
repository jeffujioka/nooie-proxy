"""nooie-proxy: sign in to a nooie camera and put its stream on stdout."""

import asyncio
import sys

import aiohttp

from . import apeman, cloud
from .env import load_environment, log, output
from .stream import stream


async def serve() -> None:
    target = output()
    async with aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=30)
    ) as http:
        config = await cloud.login(http)
        # publish our nat mapping on nooie's p2p network so the camera can
        # reach us; the registration holds its udp socket open.
        registration = await asyncio.to_thread(apeman.register, config.uid)
        # enough of the mapping to tell a nat problem apart from a working
        # one, without putting the user's public address in a log they may
        # well paste into an issue.
        masked = registration.wan_ip.rsplit(".", 1)[0] + ".x"
        log(f"p2p registered from {masked}")
        await stream(config, target)


async def list_devices() -> None:
    """print every camera on the account so NOOIE_DEVICE_ID can be chosen."""
    async with aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=30)
    ) as http:
        _, devices = await cloud.signed_in(http)
    print("uuid\tname\tmodel\tonline")
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
    try:
        if "--list-devices" in argv:
            asyncio.run(list_devices())
        else:
            asyncio.run(serve())
    except (RuntimeError, OSError, aiohttp.ClientError) as error:
        # whatever reads this keeps the last line, and the last line of a
        # traceback is the least useful part of it. these are the failures
        # the account and the network raise: say them and stop.
        raise SystemExit(str(error)) from None
