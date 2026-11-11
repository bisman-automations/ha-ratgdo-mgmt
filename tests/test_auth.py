"""HomeKit X-API-Key and Digest, including the RFC 2617 vector."""

from __future__ import annotations

from custom_components.ratgdo_mgmt.auth import (
    api_key,
    authorization_for_challenge,
    digest_authorization,
    parse_www_authenticate,
)
from custom_components.ratgdo_mgmt.const import AUTH_REALM


def test_default_password_matches_the_firmware_hash() -> None:
    """config.cpp ships 10d3c00fa1e09696601ef113b99f8a87 for admin/password."""
    assert api_key("admin", "password") == "10d3c00fa1e09696601ef113b99f8a87"
    assert api_key("admin", "password", AUTH_REALM) == api_key("admin", "password")


def test_rfc_2617_digest_response() -> None:
    """The response hash matches the worked example in RFC 2617."""
    header = (
        'Digest realm="testrealm@host.com", '
        'nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", '
        'opaque="5ccc069c403ebaf9f0171e9517f40e41", '
        'qop="auth"'
    )
    challenge = parse_www_authenticate(header)
    assert challenge is not None
    authorization = digest_authorization(
        username="Mufasa",
        password="Circle Of Life",
        method="GET",
        uri="/dir/index.html",
        challenge=challenge,
        cnonce="0a4f113b",
        nc="00000001",
    )
    assert 'response="6629fae49393a05397450978507c4ef1"' in authorization
    assert 'uri="/dir/index.html"' in authorization
    built = authorization_for_challenge(
        header,
        username="Mufasa",
        password="Circle Of Life",
        method="GET",
        uri="/dir/index.html",
    )
    assert built is not None
    assert built.startswith("Digest ")
