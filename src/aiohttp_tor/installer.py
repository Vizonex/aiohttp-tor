"""
Installer
---------

Requrired for installation of the tor-expert-bundle. A Special installer
was made inspired by pypetteer for trying to install tor onto anything.
"""

import asyncio
from datetime import datetime
from functools import total_ordering
from re import compile as re_compile
from typing import Optional

from aiohttp import request
from async_lru import alru_cache
from attrs import define
from yarl import URL

# We have to webscrape tor to figure out the current version so that we can get the right expert bundle.

ARCHIVE = URL("https://archive.torproject.org/tor-package-archive/torbrowser/")

VERSION_RE = re_compile(r"([0-9]+\.[0-9]+(?:[a\.][0-9]+)?\/)<\/a>\s+([0-9\-]+)")


@define
@total_ordering
class TorVersion:
    major: int
    minor: int
    patch: Optional[int] = None
    alpha: Optional[int] = None
    release_date: Optional[datetime] = None

    def __gt__(self, other: "TorVersion"):
        if not isinstance(other, TorVersion):
            return False
        return (self.major, self.minor, self.patch, self.alpha) > (
            other.major,
            other.minor,
            other.minor,
            other.patch,
        )

    @classmethod
    def from_str(cls, version: str):
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
        return (
            f"{self.major}.{self.minor}a{self.alpha}"
            if not self.patch
            else f"{self.major}.{self.minor}.{self.patch}"
        )


def filter_by_latest_and_stable(versions: list[TorVersion]):
    return max(filter(lambda x: not x.alpha, versions))


def parse_html(data: str) -> list[TorVersion]:
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
async def get_versions() -> list[TorVersion]:
    async with request("GET", ARCHIVE) as resp:
        data = await resp.text()
    return await asyncio.to_thread(parse_html, data)
