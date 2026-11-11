"""Pytest fixtures for ratgdo Mgmt."""

from __future__ import annotations

from collections.abc import Generator
from typing import Any

import pytest


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(
    enable_custom_integrations: Generator[None],
) -> Generator[None]:
    """Load custom integrations for every test."""
    yield


@pytest.fixture(autouse=True)
def _no_github(monkeypatch: pytest.MonkeyPatch) -> None:
    """Do not call GitHub during unit tests."""

    async def _fetch(*_args: Any, **_kwargs: Any) -> None:
        return None

    monkeypatch.setattr(
        "custom_components.ratgdo_mgmt.coordinator.async_fetch_latest", _fetch
    )
