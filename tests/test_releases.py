"""Version comparison against the firmware's actual tag shapes."""

from __future__ import annotations

from custom_components.ratgdo_mgmt.releases import (
    comparable,
    is_newer,
    latest_for_entity,
    repo_for,
    strip_tag,
)


def test_homekit_semver_compares_and_esphome_build_numbers_do_not() -> None:
    """2.2.5 is older than 2.2.6. A board profile is not older than build 1635."""
    assert strip_tag("v2.2.6") == "2.2.6"
    assert is_newer("2.2.5", "2.2.6") is True
    assert is_newer("3.5.6", "3.5.6") is False
    assert comparable("2.5", "1635") is False
    assert is_newer("2.5", "1635") is False
    assert is_newer("32disco", "1635") is False
    assert latest_for_entity("2.5", "1635") == "2.5"
    assert latest_for_entity("2.2.5", "2.2.6") == "2.2.6"


def test_repo_is_whitelisted() -> None:
    """A gitRepo the device invented is not fetched."""
    assert repo_for("homekit", "homekit-ratgdo") == "homekit-ratgdo"
    assert repo_for("homekit", "homekit-ratgdo32") == "homekit-ratgdo32"
    assert repo_for("homekit", "someone-else") is None
    assert repo_for("esphome", None) == "esphome-ratgdo"
