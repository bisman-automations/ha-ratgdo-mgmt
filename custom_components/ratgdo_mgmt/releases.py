"""GitHub release lookup for the firmware a controller is running.

HomeKit firmware reports ``firmwareVersion`` as the same semver the tag
uses (``v2.2.6`` on ``ratgdo/homekit-ratgdo``, ``v3.5.6`` on
``ratgdo/homekit-ratgdo32``). Those compare directly.

ESPHome's ``project_version`` is the board profile from the YAML
(``2.5``, ``2.5i``, ``32disco``, ``2.0``). The ``esphome-ratgdo`` release
tags are build numbers (``v1635``). Those two strings are not the same
kind of version, so a board profile is not reported as "older than"
build 1635. The release is still fetched and linked. A comparison is
made only when both sides have the same shape (both ``x.y.z``, both
``x.y``, or both a build number).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import logging
import re
from typing import Any

from aiohttp import ClientError, ClientTimeout
from packaging.version import InvalidVersion, Version

from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.util import dt as dt_util

from .const import (
    ESPHOME_GITHUB_REPO,
    FIRMWARE_ESPHOME,
    FIRMWARE_HOMEKIT,
    GITHUB_OWNER,
    HOMEKIT_REPOS,
    RELEASE_INTERVAL,
)

_LOGGER = logging.getLogger(__name__)

_USER_AGENT = "ratgdo-mgmt (https://github.com/bisman-automations/ha-ratgdo-mgmt)"
_SEMVER = re.compile(r"^\d+\.\d+\.\d+$")
_MINOR = re.compile(r"^\d+\.\d+$")
_BUILD = re.compile(r"^\d{3,}$")


@dataclass(slots=True)
class ReleaseInfo:
    """The newest GitHub release for one firmware repository."""

    repo: str
    version: str
    url: str
    notes: str | None
    fetched: datetime


def repo_for(firmware: str | None, git_repo: str | None) -> str | None:
    """Return the GitHub repo name to query, or None when it is not ours.

    ``gitRepo`` is taken from the device, so only the two official HomeKit
    names are honored. Anything else is ignored rather than fetched.
    """
    if firmware == FIRMWARE_HOMEKIT and git_repo in HOMEKIT_REPOS:
        return git_repo
    if firmware == FIRMWARE_ESPHOME:
        return ESPHOME_GITHUB_REPO
    return None


def release_url(firmware: str | None, git_repo: str | None) -> str | None:
    """Return the releases page for this firmware, even before a fetch."""
    repo = repo_for(firmware, git_repo)
    if repo is None:
        return None
    return f"https://github.com/{GITHUB_OWNER}/{repo}/releases"


def strip_tag(tag: str) -> str:
    """Return a tag without one leading ``v``."""
    text = tag.strip()
    if text[:1] in {"v", "V"} and len(text) > 1 and text[1].isdigit():
        return text[1:]
    return text


def _shape(value: str) -> str | None:
    """Return semver, minor, or build when ``value`` is one of those."""
    if _SEMVER.fullmatch(value):
        return "semver"
    if _MINOR.fullmatch(value):
        return "minor"
    if _BUILD.fullmatch(value):
        return "build"
    return None


def comparable(installed: str | None, latest: str | None) -> bool:
    """Return True when the two strings are the same kind of version."""
    if not installed or not latest:
        return False
    left = _shape(installed.strip())
    right = _shape(latest.strip())
    return left is not None and left == right


def is_newer(installed: str | None, latest: str | None) -> bool:
    """Return True when ``latest`` is a newer comparable version."""
    if not comparable(installed, latest) or installed is None or latest is None:
        return False
    try:
        return Version(latest.strip()) > Version(installed.strip())
    except InvalidVersion:
        return False


def latest_for_entity(installed: str | None, release: str | None) -> str | None:
    """Return the version the update entity should call latest.

    When the GitHub tag is not the same kind of number the device reports,
    the entity stays "up to date" for that string and the tag is exposed
    separately. Home Assistant turns the entity on whenever latest and
    installed differ, which would be a false update for ``2.5`` versus
    ``1635``.
    """
    if release and is_newer(installed, release):
        return release
    return installed


async def async_fetch_latest(hass: HomeAssistant, repo: str) -> ReleaseInfo | None:
    """Return the newest release of ``ratgdo/<repo>``, or None when GitHub is quiet."""
    url = f"https://api.github.com/repos/{GITHUB_OWNER}/{repo}/releases/latest"
    session = async_get_clientsession(hass)
    try:
        async with session.get(
            url,
            timeout=ClientTimeout(total=20),
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": _USER_AGENT,
            },
        ) as response:
            if response.status != 200:
                _LOGGER.debug("GitHub %s returned HTTP %s", url, response.status)
                return None
            payload: Any = await response.json(content_type=None)
    except (ClientError, TimeoutError, ValueError) as err:
        _LOGGER.debug("GitHub %s failed: %s", url, err)
        return None
    if not isinstance(payload, dict):
        return None
    tag = payload.get("tag_name")
    html = payload.get("html_url")
    if not isinstance(tag, str) or not tag.strip():
        return None
    if not isinstance(html, str) or not html.startswith("https://github.com/"):
        html = f"https://github.com/{GITHUB_OWNER}/{repo}/releases/tag/{tag}"
    notes = payload.get("body")
    return ReleaseInfo(
        repo=repo,
        version=strip_tag(tag),
        url=html,
        notes=notes if isinstance(notes, str) and notes.strip() else None,
        fetched=dt_util.utcnow(),
    )


def stale(info: ReleaseInfo | None, now: datetime) -> bool:
    """Return True when a cached release should be fetched again."""
    if info is None:
        return True
    return now - info.fetched >= RELEASE_INTERVAL
