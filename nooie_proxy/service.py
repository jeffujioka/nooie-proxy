"""nooie-proxy: sign in to a nooie camera and put its stream on stdout."""

import asyncio

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


def main() -> None:
    load_environment()
    asyncio.run(serve())
