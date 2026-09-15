#!/usr/bin/env python3
"""The Orizon Agents reference external agent.

    $ pip install pynacl
    $ python3 agent.py

One file. One third-party dependency. Read it top to bottom and you will know
everything an operator needs to know about receiving a dispatch safely.

WHAT THIS IS
    Orizon's orchestrator plans a buyer's workflow, picks an agent for each
    step, and POSTs that step as a JSON envelope to the HTTPS endpoint the
    agent's operator bound. This file is the other side of that POST: a
    stdlib HTTP server that verifies the request really came from Orizon,
    does a small piece of work inside the budget it was given, and answers in
    the shape the orchestrator accepts.

    It is a STARTING POINT, not a framework. Replace `run_step` with your real
    agent; keep everything above and below it.

WHY ONLY PyNaCl
    `stellar-sdk` would give us `Keypair.verify_message` in one line, and cost
    seven transitive dependencies and ~12 MB to do it. Every dependency is a
    chance for your environment to differ from ours, in a service whose whole
    job is to be reachable and correct at 3am. stellar-sdk is itself a thin
    wrapper over PyNaCl for this primitive, so we call PyNaCl directly and
    write the two pieces of framing out by hand — the SEP-53 message hash and
    the strkey decode. They are twenty lines between them, and having them
    visible teaches what a `G…` address and a Stellar signature actually are.

NO SECRETS LIVE HERE
    This agent verifies signatures; it never makes any. It holds no private
    key, so there is nothing in this file, its comments, or its defaults worth
    stealing. Everything deployment-specific comes from the environment.

CONFIGURATION (environment variables, all optional, all safe by default)

    ORIZON_ENDPOINT_URL   The URL you bound with Orizon, EXACTLY as you
                          registered it. It is part of the signed message, so
                          a trailing slash or a http/https mismatch here means
                          every signature fails. Default is the local dev URL.
    ORIZON_SIGNER         The `G…` address you pinned out of band, from
                          GET /api/stellar/network → `dispatch_signer`.
                          Empty (the default) means "not configured yet" and
                          puts this agent in its loud, unverified mode.
    ORIZON_NETWORK        `testnet` or `public`. Must match `network` in the
                          envelope. Default `testnet`.
    ORIZON_HOST           Listen address. Default 127.0.0.1 — bind to
                          127.0.0.1 and put TLS in front; see `main`.
    ORIZON_PORT           Listen port. Default 8787.
    ORIZON_MAX_SKEW       Accepted clock skew on `ts`, seconds. Default 300,
                          which is what the operator doc specifies.
    ORIZON_MAX_BODY       Largest request body accepted, bytes. Default 8 MiB.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import html
import json
import logging
import os
import re
import struct
import threading
import time
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

logger = logging.getLogger("orizon.agent")


# ---------------------------------------------------------------------------
# The wire contract. These are Orizon's values, not yours — do not tune them.
# ---------------------------------------------------------------------------

# Envelope version we understand. A future `v` we do not recognise is answered,
# not refused: the fields we read are additive so far, and refusing an envelope
# we could have served is a failed step we chose for ourselves.
ENVELOPE_VERSION = 2

# The signed-message format, domain-separated and versioned. A v2 signature
# would simply stop verifying here rather than being silently accepted.
SIG_VERSION = "orizon-dispatch:v1"

SIGNATURE_HEADER = "X-Orizon-Signature"
SIG_VERSION_HEADER = "X-Orizon-Signature-Version"
# CONVENIENCE ONLY. See `verify_dispatch` — this header is never trusted.
SIGNER_HEADER = "X-Orizon-Signer"
IDEMPOTENCY_HEADER = "Idempotency-Key"

# SEP-53's domain separator. Stellar signs the SHA-256 of this prefix followed
# by the message, never the message itself, so that a signature over an
# arbitrary blob can never also be a valid signature over a transaction
# envelope. Reproducing the framing is the whole of `sep53_message_hash`.
SEP53_PREFIX = b"Stellar Signed Message:\n"

# Orizon streams our response and cuts it off unread past this, which fails the
# step as `oversize_response`. We clamp ourselves rather than find out.
MAX_RESPONSE_BYTES = 1_048_576

# The clamps the orchestrator applies to each field it accepts. Applying them
# here too is not belt-and-braces: a field clamped on their side comes back
# truncated with a "…[truncated]" marker in the buyer's trace, which reads as
# sloppiness from your agent. Values from app/agents/workers/external_contract.py.
MAX_SUMMARY_CHARS = 2_000
MAX_TITLE_CHARS = 120
MAX_FILES = 24
MAX_PATH_CHARS = 200
MAX_FILE_CHARS = 120_000
MAX_NOTES = 16
MAX_NOTE_CHARS = 500


# ---------------------------------------------------------------------------
# Configuration. Read once at import, from the environment, with defaults that
# are safe to run as-is on a laptop and obviously wrong to run in production.
# ---------------------------------------------------------------------------


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default).strip()


def _env_int(name: str, default: int) -> int:
    raw = _env(name, str(default))
    try:
        return int(raw)
    except ValueError:
        # A typo in an env var must not silently weaken a bound. Say so and use
        # the default, which is the conservative value in every case here.
        logger.warning("%s=%r is not an integer — using %d", name, raw, default)
        return default


ENDPOINT_URL = _env("ORIZON_ENDPOINT_URL", "http://127.0.0.1:8787/dispatch")
PINNED_SIGNER = _env("ORIZON_SIGNER", "")
EXPECTED_NETWORK = _env("ORIZON_NETWORK", "testnet")
LISTEN_HOST = _env("ORIZON_HOST", "127.0.0.1")
LISTEN_PORT = _env_int("ORIZON_PORT", 8787)
MAX_SKEW_SECONDS = _env_int("ORIZON_MAX_SKEW", 300)
# Bounded before a single byte is read. `context` carries the output of every
# prior step in the workflow, so a legitimate envelope can be large — but
# "large" is not "unbounded", and an unbounded read is a one-line denial of
# service against a process with no memory limit.
MAX_BODY_BYTES = _env_int("ORIZON_MAX_BODY", 8 * 1024 * 1024)


# ---------------------------------------------------------------------------
# What a `G…` address actually is
# ---------------------------------------------------------------------------


def decode_g_address(address: str) -> bytes:
    """Decode a Stellar `G…` strkey to the 32 raw ed25519 public-key bytes.

    A `G…` address is not a key. It is a 35-byte envelope, base32-encoded
    without padding:

        byte  0      version byte 0x30 — "ed25519 public key", which is what
                     makes every one of them start with the letter G
        bytes 1..32  the actual 32-byte ed25519 public key
        bytes 33,34  CRC16-XMODEM over the first 33 bytes, little-endian

    35 bytes is 280 bits, which is exactly 56 base32 characters, which is why
    every Stellar address is 56 characters long and never carries an `=`.

    The checksum is a TYPO guard, not a security control: it catches an address
    mangled by a copy-paste or a line wrap, and catches nothing an adversary
    does, because an adversary computes the checksum too. It is checked anyway
    because the failure it prevents — pinning a corrupted signer and then
    debugging "every signature is invalid" for an afternoon — is exactly the
    failure an operator hits on day one.

    Raises ValueError, with a message that quotes nothing: an address is public
    so there is no secret to leak here, but the same function shape is the one
    you would reuse for an `S…` secret, and that one must never echo its input.
    """
    if len(address) != 56 or not address.startswith("G"):
        raise ValueError("not a 56-character address starting with G")
    try:
        # b32decode is strict about case and length; both are what we want. A
        # lowercased address is a mangled address, not a convenience to absorb.
        decoded = base64.b32decode(address.encode("ascii"))
    except (binascii.Error, ValueError) as e:
        raise ValueError("not valid base32") from e
    if len(decoded) != 35:  # pragma: no cover — implied by the length check above
        raise ValueError("wrong decoded length")
    payload, checksum = decoded[:-2], decoded[-2:]
    if decoded[0] != 0x30:
        raise ValueError("version byte is not an ed25519 public key")
    # crc_hqx IS CRC16-XMODEM (poly 0x1021, init 0x0000) and is stdlib; `<H`
    # packs it little-endian, which is the byte order Stellar stores it in.
    if struct.pack("<H", binascii.crc_hqx(payload, 0)) != checksum:
        raise ValueError("checksum mismatch — the address is mistyped or truncated")
    return decoded[1:-2]


def sep53_message_hash(message: str) -> bytes:
    """The 32 bytes a Stellar signer actually signs for a SEP-53 message.

        sha256(b"Stellar Signed Message:\\n" + message.encode("utf-8"))

    The prefix is the entire point. Raw `Keypair.sign()` has NO domain
    separation: a signature over attacker-chosen bytes is structurally
    indistinguishable from a signature over a transaction envelope, separated
    only by length. Prefixing means a signature produced for a message can
    never be replayed as a signature authorising a payment, and vice versa.

    This is three lines because it is three lines. `stellar_sdk`'s
    `Keypair.verify_message` is this hash followed by an ed25519 verify — the
    same two operations, behind an import that brings six other packages.
    """
    return hashlib.sha256(SEP53_PREFIX + message.encode("utf-8")).digest()


def dispatch_message(endpoint_url: str, raw_body: bytes) -> str:
    """The exact string Orizon signed for one dispatch.

        orizon-dispatch:v1:{endpoint_url}:{sha256_hex(body)}

    TWO THINGS HERE ARE LOAD-BEARING.

    `endpoint_url` is NOT transmitted. It is not in the body and it is not in a
    header; the only copy on your side is the one in your own configuration.
    That is what makes a dispatch signature non-transferable. If the URL rode
    along in the request, a competing operator who received a dispatch could
    replay the whole signed envelope at YOUR endpoint, your verification would
    pass, and you would run — and bill — a job Orizon never sent you. Because
    the URL comes from your config, their envelope rebuilds a different message
    here and fails. You get that property for free, with nothing to remember.

    `raw_body` is hashed, not embedded, so this string stays a bounded thing
    you can log whatever the envelope grows into. It must be the bytes AS
    RECEIVED — see `verify_dispatch`.
    """
    return f"{SIG_VERSION}:{endpoint_url}:{hashlib.sha256(raw_body).hexdigest()}"
