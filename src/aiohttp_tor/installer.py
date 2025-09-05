"""
Installer
---------

Requrired for installation of the tor-expert-bundle. A Special installer
was made inspired by pypetteer for trying to install tor onto anything.
"""

from __future__ import annotations

import asyncio
import os
import platform
import sys
from datetime import datetime
from functools import lru_cache, total_ordering
from pathlib import Path
from re import compile as re_compile
from typing import Any, Optional, Type

from aiofiles import open as aopen
from aiohttp import BaseConnector, request
from async_lru import alru_cache
from attrs import define, field
from propcache import under_cached_property
from yarl import URL

from .typedefs import Self

# We have to webscrape tor to figure out the current version so that we can get the right expert bundle.

ARCHIVE = URL("https://archive.torproject.org/tor-package-archive/torbrowser/")

VERSION_RE = re_compile(r"([0-9]+\.[0-9]+(?:[a\.][0-9]+)?\/)<\/a>\s+([0-9\-]+)")

IS_64BIT = sys.maxsize > 2**32


class UnknownPlatform(Exception):
    """Platform was deemed as being unknown"""

    def __init__(self, platform: str, machine: str):
        """
        initalize unknown platform exception

        :param platform: the platform that couldn't be determined
        :param machine: the machine for the platform that wasn't
            supported or propperly guessed.
        """
        self.platform = platform
        self.machine = machine

    def __str__(self):
        return f"platform: {self.platform} with machine: {self.machine} is currently unknown or unsupported"


@lru_cache
def _platform_and_arch():
    """return a best guess on what arch and platform to use for which
    tor-expert-bundle to install on any given machine
    
    Raises
    ------

    UnknownPlatform
        if platform and machine couldn't be determined and doesn't have a provided release.
    
    """
    machine = platform.machine().lower()

    # NOTE: On ubuntu there's a sourceforge release that I didn't account
    # for, You'll have to look it up since I forgot the link.

    # If I get any of these predictions wrong please throw an issue on github
    # since tor is not something that can be simply ran in pytest
    if sys.platform == "andriod":
        if not machine or (machine in ["armv7", "x86", "aarch64", "x86_64"]):
            return "android-x86_64" if IS_64BIT else "android-x86"
        return f"android-{machine}"
    elif sys.platform.startswith("linux"):
        return "linux-x86_64" if IS_64BIT else "linux-i686"

    elif sys.platform == "darwin":
        return "macos-aarch64" if IS_64BIT else "macos-x86_64"

    elif sys.platform in ["win32", "cygwin"]:
        return "windows-x86_64" if IS_64BIT else "windows-i686"

    raise UnknownPlatform(sys.platform, machine or "Unknown-Machine")


@define
@total_ordering
class TorVersion:
    """Version of tor to attempt to download"""

    major: int
    minor: int
    patch: Optional[int] = None
    alpha: Optional[int] = None
    release_date: Optional[datetime] = None

    def __gt__(self, other: "TorVersion") -> bool:
        if not isinstance(other, TorVersion):
            return False
        return (self.major, self.minor, self.patch, self.alpha) > (
            other.major,
            other.minor,
            other.minor,
            other.patch,
        )

    @classmethod
    def from_str(cls: Type[Self], version: str) -> Self:
        """return a version of Tor from a given string

        :param version: the version to convert

        :returns: A `TorVersion` object
        """
        major, minor = version.strip("/").split("-", 1)[0].split(".", 1)
        if "a" in minor:
            minor, alpha = minor.split("a", 1)
            patch = None
        elif "." in minor:
            minor, patch = minor.split(".", 1)
            alpha = None
        else:
            patch = None
            alpha = None
        return cls(
            int(major),
            int(minor),
            int(patch) if patch else 0,
            int(alpha) if alpha else 0,
        )

    def __str__(self):
        """Return a Representation of a tor version as it's original string"""
        return (
            f"{self.major}.{self.minor}a{self.alpha}"
            if not self.patch
            else f"{self.major}.{self.minor}.{self.patch}"
        )

    async def install(
        self,
        installation_name: str = "tor-expert-bundle.tar.gz",
        path: Path | str | None = None,
        connector: BaseConnector | None = None,
        loop: asyncio.AbstractEventLoop | None = None,
    ) -> Path:
        """return where tor was installed from."""
        version_str = self.__str__()
        plat_and_arch = _platform_and_arch()
        installation_path = Path(path or os.getcwd()) / installation_name

        async with request(
            "GET",
            ARCHIVE
            / version_str
            / f"tor-expert-bundle-{plat_and_arch}-{version_str}.tar.gz",
            connector=connector,
            loop=loop,
            raise_for_status=True,
        ) as resp:
            async with aopen(installation_path, "wb") as wb:
                async for bits in resp.content.iter_chunked(1024):
                    await wb.write(bits)

        return installation_path


@define
class TorVersionList:
    """A collection of tor versions to sort through"""

    versions: list[TorVersion] = field(factory=list)
    _cache: dict[str, Any] = field(factory=dict, init=False)

    @under_cached_property
    def latest_stable_version(self) -> TorVersion:
        """return latest version of tor that is stable.
        This property is immutable and modifications are discouraged"""
        return max(filter(lambda x: not x.alpha, self.versions))

    @under_cached_property
    def latest_version(self) -> TorVersion:
        """return latest version of tor even if it's still
        in beta even if it's not ready for general public use.
        This property is immutable and modifications are discouraged"""
        return max(self.versions)


def _parse_html(data: str) -> list[TorVersion]:
    versions: list[TorVersion] = []
    for i in VERSION_RE.finditer(data):
        tv = TorVersion.from_str(i.group(1))
        year, month, day = i.group(2).split("-", 2)
        tv.release_date = datetime(
            int(year), int(month.rstrip("0")), int(day.rstrip("0"))
        )
        versions.append(tv)
    return versions


@alru_cache(ttl=600)  # 10 minute intervals.
async def get_versions(
    connector: BaseConnector | None = None,
    loop: asyncio.AbstractEventLoop | None = None,
) -> TorVersionList:
    """
    return a list of compatable versions of tor from `archive.torproject.org <https://archive.torproject.org/tor-package-archive/torbrowser>`__

    :param connector: a custom connector to use if any for the request (Example could be a proxy from aiohttp-socks)
    :param loop: an eventloop in use otherwise aiohttp will grab one to utilize.

    :returns: a list of different versions of tor as a dataclass to sort through
    """
    async with request("GET", ARCHIVE, connector=connector, loop=loop) as resp:
        data = await resp.text()
    return TorVersionList(await asyncio.to_thread(_parse_html, data))

# TODO: in a later update, add install_latest_version & install_latest_unstable_version()

