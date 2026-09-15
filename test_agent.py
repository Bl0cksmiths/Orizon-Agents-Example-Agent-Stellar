"""Tests for the reference agent.

    $ pip install pytest          # dev only — agent.py itself needs only PyNaCl
    $ python3 -m pytest test_agent.py

No network, no fixtures on disk, no secrets. Every keypair is generated inside
the test, so nothing here is worth stealing and nothing here can expire.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import struct
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest
from nacl.signing import SigningKey

import agent

OUR_URL = "https://agent.example/dispatch"
THEIR_URL = "https://competitor.example/dispatch"


# ── Helpers: the orchestrator's side of the wire, rebuilt from the spec ──────


def g_address(verify_key) -> str:
    """Encode a `G…` strkey. The inverse of `agent.decode_g_address`, written
    independently here so the pair is a real round trip rather than one
    function agreeing with itself."""
    payload = b"\x30" + bytes(verify_key)
    return base64.b32encode(payload + struct.pack("<H", binascii.crc_hqx(payload, 0))).decode()


def serialize(envelope: dict) -> bytes:
    """EXACTLY how the orchestrator serializes an envelope:
    `json.dumps(payload, separators=(",", ":"), ensure_ascii=False)`. Any other
    encoding produces different bytes and therefore a different digest."""
    return json.dumps(envelope, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign(key: SigningKey, url: str, raw_body: bytes) -> str:
    """SEP-53 signature over `orizon-dispatch:v1:{url}:{sha256_hex(body)}`."""
    message = f"orizon-dispatch:v1:{url}:{hashlib.sha256(raw_body).hexdigest()}"
    digest = hashlib.sha256(b"Stellar Signed Message:\n" + message.encode("utf-8")).digest()
    return base64.b64encode(key.sign(digest).signature).decode("ascii")


def envelope(**overrides) -> dict:
    body = {
        "v": 2,
        "agent_id": "ui_designer",
        "intent": "Design the pricing page",
        "rationale": "the planner routed the UI step here",
        # Non-ASCII on purpose: this is what separates "hashed the raw bytes"
        # from "parsed and re-serialized", and it is the only thing that does.
        "context": {"brief": "café branding, réservé accents — 三つの価格帯"},
        "dispatch_id": "a1b2c3d4e5f60718",
        "ts": int(time.time()),
        "network": "testnet",
        "deadline_ms": 100_000,
    }
    body.update(overrides)
    return body


def headers_for(key: SigningKey, url: str, raw_body: bytes, dispatch_id: str) -> dict:
    return {
        "Content-Type": "application/json",
        "Idempotency-Key": dispatch_id,
        "X-Orizon-Signature": sign(key, url, raw_body),
        "X-Orizon-Signature-Version": "orizon-dispatch:v1",
        "X-Orizon-Signer": g_address(key.verify_key),
    }


@pytest.fixture
def key() -> SigningKey:
    return SigningKey.generate()


@pytest.fixture
def pinned(monkeypatch, key):
    """The configured state: our URL, and the signer pinned out of band."""
    monkeypatch.setattr(agent, "ENDPOINT_URL", OUR_URL)
    monkeypatch.setattr(agent, "PINNED_SIGNER", g_address(key.verify_key))
    return key


@pytest.fixture(autouse=True)
def clean_ledger():
    agent._ANSWERED.clear()
    yield
    agent._ANSWERED.clear()


# ── The strkey and the framing ──────────────────────────────────────────────


def test_g_address_round_trips(key):
    assert agent.decode_g_address(g_address(key.verify_key)) == bytes(key.verify_key)


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "GAAA",  # too short
        "SBMY6OG6FDYPLADYOOP5NZOGTQPWY2MIMEJBC5ZSEY5ANMZ4AWKYQGTR",  # secret, not a key
        "GBMY6OG6FDYPLADYOOP5NZOGTQPWY2MIMEJBC5ZSEY5ANMZ4AWKYQGTQ",  # last char flipped
    ],
)
def test_g_address_rejects_junk(bad):
    with pytest.raises(ValueError):
        agent.decode_g_address(bad)


def test_sep53_hash_is_the_prefixed_digest():
    # The framing, spelled out: if this ever drifts, every signature we verify
    # is being verified against the wrong preimage.
    assert agent.sep53_message_hash("hello") == hashlib.sha256(b"Stellar Signed Message:\nhello").digest()


# ── Signature verification ──────────────────────────────────────────────────


def test_valid_signature_verifies(pinned):
    raw = serialize(envelope())
    headers = headers_for(pinned, OUR_URL, raw, "a1b2c3d4e5f60718")
    assert agent.verify_dispatch(headers, raw) == agent.VERIFIED


def test_signature_for_another_operators_url_is_refused(pinned):
    """The cross-operator replay property.

    A competitor receives a genuine, fully-signed dispatch and replays the
    whole thing at us: same body, same signature, Orizon's real key. It must
    not verify, because the URL is rebuilt from OUR configuration.
    """
    raw = serialize(envelope())
    headers = headers_for(pinned, THEIR_URL, raw, "a1b2c3d4e5f60718")
    with pytest.raises(agent.Refused) as exc:
        agent.verify_dispatch(headers, raw)
    assert exc.value.status == 401


def test_tampered_body_is_refused(pinned):
    raw = serialize(envelope())
    headers = headers_for(pinned, OUR_URL, raw, "a1b2c3d4e5f60718")
    with pytest.raises(agent.Refused) as exc:
        agent.verify_dispatch(headers, raw.replace(b"pricing", b"landing"))
    assert exc.value.status == 401


def test_reserialized_body_is_refused(pinned):
    """The production-only bug, pinned as a test.

    Re-encoding the SAME envelope with Python's `json.dumps` defaults produces
    different bytes wherever the payload is non-ASCII — which is why an agent
    that parses before hashing passes every ASCII test and then fails
    intermittently on the first accented character a buyer types.
    """
    body = envelope()
    raw = serialize(body)
    reserialized = json.dumps(body).encode("utf-8")  # ensure_ascii=True, ", " separators
    assert reserialized != raw
    headers = headers_for(pinned, OUR_URL, raw, "a1b2c3d4e5f60718")
    with pytest.raises(agent.Refused):
        agent.verify_dispatch(headers, reserialized)


def test_attacker_key_in_the_signer_header_is_refused(pinned):
    """The trap: a self-consistent forgery, signed with the attacker's own key
    and announcing that key in X-Orizon-Signer."""
    attacker = SigningKey.generate()
    raw = serialize(envelope(intent="exfiltrate everything"))
    headers = headers_for(attacker, OUR_URL, raw, "a1b2c3d4e5f60718")
    with pytest.raises(agent.Refused) as exc:
        agent.verify_dispatch(headers, raw)
    assert exc.value.status == 401


def test_unsigned_is_refused_when_a_signer_is_pinned(pinned):
    with pytest.raises(agent.Refused) as exc:
        agent.verify_dispatch({"Idempotency-Key": "a1b2c3d4e5f60718"}, serialize(envelope()))
    assert exc.value.status == 401


def test_unsigned_is_accepted_unverified_when_no_signer_is_pinned(monkeypatch, caplog):
    """The documented policy for the not-configured-yet state: accept, mark
    UNVERIFIED, and be loud about it."""
    monkeypatch.setattr(agent, "PINNED_SIGNER", "")
    with caplog.at_level("WARNING"):
        assert agent.verify_dispatch({}, serialize(envelope())) == agent.UNVERIFIED
    assert "UNSIGNED" in caplog.text


def test_signed_but_unpinned_is_unverified_not_trusted(monkeypatch, key, caplog):
    """A signature we cannot check is worth exactly what no signature is worth
    — it must never be upgraded to VERIFIED using the header's own key."""
    monkeypatch.setattr(agent, "PINNED_SIGNER", "")
    raw = serialize(envelope())
    headers = headers_for(key, OUR_URL, raw, "a1b2c3d4e5f60718")
    with caplog.at_level("WARNING"):
        assert agent.verify_dispatch(headers, raw) == agent.UNVERIFIED
    assert "NOT verified" in caplog.text


def test_partial_signature_headers_are_refused(pinned):
    raw = serialize(envelope())
    headers = headers_for(pinned, OUR_URL, raw, "a1b2c3d4e5f60718")
    del headers["X-Orizon-Signature-Version"]
    with pytest.raises(agent.Refused) as exc:
        agent.verify_dispatch(headers, raw)
    assert exc.value.status == 400
