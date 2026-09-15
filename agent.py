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


# ---------------------------------------------------------------------------
# Verifying that a request really came from Orizon
# ---------------------------------------------------------------------------


class Refused(Exception):
    """A request we will not run. `status` is the HTTP status to answer with.

    Refusing costs the operator nothing: a non-2xx fails the step as
    `error_status`, which is not billed. Running a forged step costs you the
    compute AND puts output you did not author into a buyer's workflow under
    your agent id. When in doubt, refuse.
    """

    def __init__(self, status: int, reason: str) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason


# Verification outcomes, in the order of how much they let you trust the caller.
VERIFIED = "verified"  # signature checked against the pinned signer
UNVERIFIED = "unverified"  # accepted without proof — see the policy below


def verify_dispatch(headers, raw_body: bytes) -> str:
    """Decide whether to run this request. Returns VERIFIED or UNVERIFIED,
    or raises `Refused`.

    `raw_body` MUST be the bytes off the socket, before `json.loads`. This is
    the single most common way to get this wrong. If you parse first and
    re-serialize to hash, you are hashing YOUR encoder's output, not Orizon's:
    Python's `json.dumps` defaults to `ensure_ascii=True` and `", "`
    separators, while the orchestrator sends
    `json.dumps(payload, separators=(",", ":"), ensure_ascii=False)`. Those
    agree byte for byte on pure-ASCII payloads and diverge on the first
    accented character, emoji or CJK string a buyer types. So the bug passes
    every test you write, ships, and then fails intermittently in production
    on exactly the envelopes you cannot reproduce. Hash the raw bytes.

    ── THE UNSIGNED-REQUEST POLICY ────────────────────────────────────────────
    Orizon signs a dispatch only when the deployment has a dispatch key
    configured; a deployment without one sends no signature headers at all, and
    that is not an attack. So there are two states and this agent treats them
    differently:

      * ORIZON_SIGNER is PINNED  → a signature is REQUIRED. An unsigned request
        is refused 401. Once you know Orizon holds a key, an unsigned request
        is either a misconfiguration or someone downgrading you to no
        authentication at all, and accepting it makes pinning decorative.

      * ORIZON_SIGNER is EMPTY   → unsigned requests are accepted, every one of
        them logs a WARNING, and the result is marked UNVERIFIED so the rest of
        the file can decline to do anything expensive. This is the
        "not configured yet" state, and it is loud on purpose: a silently
        unauthenticated endpoint is how an agent ends up running strangers'
        work. Pin a signer. It takes one environment variable.

    Choose the opposite default if you like — the doc says it is your call —
    but choose it deliberately. What you must NOT do is what the header layout
    invites, which is the third branch below.
    """
    signature_b64 = headers.get(SIGNATURE_HEADER)
    version = headers.get(SIG_VERSION_HEADER)
    claimed_signer = headers.get(SIGNER_HEADER)
    present = [h for h in (signature_b64, version, claimed_signer) if h is not None]

    if not present:
        if PINNED_SIGNER:
            raise Refused(401, "unsigned dispatch, and a signer is pinned")
        logger.warning(
            "UNSIGNED dispatch accepted: ORIZON_SIGNER is not set, so anyone who can "
            "reach this endpoint can run this agent. Pin the G-address from "
            "GET /api/stellar/network -> dispatch_signer."
        )
        return UNVERIFIED

    # Some but not all of the three. Never Orizon — it adds the headers as one
    # dict — so it is a proxy stripping headers or someone probing. A partial
    # signature is worse than none: it is a claim we cannot check.
    if len(present) != 3:
        raise Refused(400, "incomplete signature headers")

    if version != SIG_VERSION:
        # A version we do not implement. Refuse rather than guess at framing:
        # verifying v2 bytes with the v1 rule is how a "successful" check ends
        # up proving nothing.
        raise Refused(400, f"unsupported signature version {version!r}")

    if not PINNED_SIGNER:
        # ── THE TRAP ──────────────────────────────────────────────────────────
        # There is a G-address RIGHT THERE in `claimed_signer`, and verifying
        # against it would make this branch pass. It would also be worthless.
        # An attacker generates a keypair, signs their own forged envelope with
        # it, puts their own public key in X-Orizon-Signer, and every check
        # succeeds — because you asked the sender who to trust. The header is a
        # debugging hint: it tells you which key Orizon BELIEVES it used, so a
        # key rotation shows up as a mismatch instead of a mystery. It is never
        # an input to the decision.
        logger.warning(
            "dispatch carries a signature but ORIZON_SIGNER is not set, so it was NOT "
            "verified. The X-Orizon-Signer header is not a substitute: anyone can set it. "
            "Pin the signer you fetched out of band."
        )
        return UNVERIFIED

    if claimed_signer != PINNED_SIGNER:
        # Logged, not merely refused, and this is the one place the header
        # earns its keep: "signed by a key that is not the one I pinned" is a
        # key rotation nine times out of ten, and you want to see it named.
        logger.warning(
            "dispatch signed by %s but %s is pinned — refusing. If Orizon rotated its "
            "dispatch key, re-fetch GET /api/stellar/network and update ORIZON_SIGNER.",
            claimed_signer,
            PINNED_SIGNER,
        )
        raise Refused(401, "signer does not match the pinned signer")

    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError) as e:
        raise Refused(400, "signature is not valid base64") from e
    if len(signature) != 64:
        raise Refused(400, "signature is not 64 bytes")

    try:
        signer_key = decode_g_address(PINNED_SIGNER)
    except ValueError as e:
        # OUR configuration is broken, not their request. 500 is honest: fixing
        # it is our job, and a 401 here would send an operator hunting for a
        # problem at Orizon's end that does not exist.
        raise Refused(500, f"ORIZON_SIGNER is not a usable address ({e})") from e

    # The URL comes from OUR configuration. Never from the request — not from a
    # Host header, not from `self.path`, not from a field in the body. An
    # attacker controls all three, and a verifier that rebuilds the message out
    # of attacker-supplied pieces verifies that the attacker is self-consistent.
    message = dispatch_message(ENDPOINT_URL, raw_body)
    try:
        VerifyKey(signer_key).verify(sep53_message_hash(message), signature)
    except BadSignatureError as e:
        raise Refused(
            401,
            "signature does not verify — if this is every request, check that "
            "ORIZON_ENDPOINT_URL is byte-identical to the URL you bound",
        ) from e
    return VERIFIED


# ---------------------------------------------------------------------------
# Checking the envelope itself
# ---------------------------------------------------------------------------

# A dispatch id is hex from `secrets.token_hex(8)`. Pinning the shape means the
# id can be used as a dict key, a log field and (if you persist results) a
# filename without any of those becoming an injection point. Anything else is
# refused rather than sanitised: sanitising invents a second id space where two
# different inputs can collapse onto one entry, and an id collision in a replay
# ledger returns one buyer's output to another.
_DISPATCH_ID_RE = re.compile(r"\A[0-9a-f]{8,64}\Z")


def _text(envelope: dict, key: str, limit: int = 20_000) -> str:
    """One string field out of the envelope, clamped, never trusted.

    Everything the buyer typed and everything a previous operator's agent
    produced arrives through fields like these. A non-string is coerced to ""
    rather than raising: the envelope's shape is Orizon's promise, but this
    function is the boundary where that promise stops being assumed.
    """
    value = envelope.get(key)
    return value[:limit] if isinstance(value, str) else ""


def check_envelope(envelope: object, headers) -> dict:
    """Validate the decoded envelope, or raise `Refused`. Returns it unchanged.

    Ordered cheapest-first, and all of it runs AFTER the signature check, so an
    unsigned caller cannot use these branches to probe what we accept.
    """
    if not isinstance(envelope, dict):
        raise Refused(400, "body is not a JSON object")

    dispatch_id = envelope.get("dispatch_id")
    if not isinstance(dispatch_id, str) or not _DISPATCH_ID_RE.match(dispatch_id):
        raise Refused(400, "dispatch_id is missing or not lowercase hex")

    # The Idempotency-Key header is OUTSIDE the signed bytes; `dispatch_id` is
    # inside them. Requiring them to be equal is what stops a proxy — or anyone
    # in the path — from rewriting the header to split one dispatch into two
    # ledger entries, or to collapse two into one. They cannot touch the body
    # copy without invalidating the signature, so pinning the header to it
    # drags the header under the signature's protection for free.
    if headers.get(IDEMPOTENCY_HEADER) != dispatch_id:
        raise Refused(400, "Idempotency-Key does not match dispatch_id")

    # Network is inside the signed bytes for a reason worth understanding: the
    # SEP-53 preimage carries no network passphrase, unlike Stellar transaction
    # signing. A testnet dispatch and a mainnet dispatch are therefore framed
    # identically, and `network` is the ONLY thing separating them. Without this
    # check, a testnet envelope — cheap to obtain — replays against a mainnet
    # agent and settles with real money behind it.
    network = envelope.get("network")
    if network != EXPECTED_NETWORK:
        raise Refused(400, f"network {network!r} is not {EXPECTED_NETWORK!r}")

    # Freshness. A signature is valid forever; `ts` is what gives it an expiry.
    # 300 s is the window the operator doc specifies — wide because it has to
    # absorb clock skew on both machines, which is also why it cannot be
    # narrowed into a useful budget. Bounding replay is the ledger's job, not
    # this check's; this one bounds how long a CAPTURED envelope stays usable.
    ts = envelope.get("ts")
    if not isinstance(ts, int) or isinstance(ts, bool):
        raise Refused(400, "ts is missing or not an integer")
    skew = abs(time.time() - ts)
    if skew > MAX_SKEW_SECONDS:
        raise Refused(
            400,
            f"ts is {skew:.0f}s away from our clock (limit {MAX_SKEW_SECONDS}s) — "
            "check NTP on this host before blaming the sender",
        )

    version = envelope.get("v")
    if isinstance(version, int) and version > ENVELOPE_VERSION:
        # Answered, not refused: every field we read has been additive so far,
        # and refusing an envelope we could have served is a failed step and a
        # 20/100 rating we chose for ourselves. Logged so you find out.
        logger.warning("envelope v%s is newer than v%d — serving it anyway", version, ENVELOPE_VERSION)
    return envelope


# ---------------------------------------------------------------------------
# Replay: the same dispatch_id must produce the same answer, not a second run
# ---------------------------------------------------------------------------


class ReplayLedger:
    """Remembers what we answered for each `dispatch_id`.

    Orizon retries a dispatch exactly once, and ONLY when the connection never
    established — so in the case it retries, you never ran. But the retry
    carries the SAME `dispatch_id`, which tells you something more useful than
    "you may ignore this": it tells you the id is the orchestrator's unit of
    work, and that answering it twice with two different results is a bug you
    are allowed to have but should not.

    So the rule is REPLAY, not reject. Returning the stored response is
    correct and free; returning an error for a duplicate turns a retry that was
    supposed to rescue a failed connection into a failed step.

    Bounded, because an id is attacker-supplied once you accept unsigned
    requests: `capacity` entries, oldest evicted first. Eviction is safe here —
    a retry follows within seconds, so an entry old enough to evict is an entry
    no retry will ask for.

    IN MEMORY, and therefore LOST ON RESTART. That is acceptable for this agent
    because a retry only happens when nothing ran, so a lost entry costs one
    duplicate execution of work that was never performed. If your agent does
    something that must not happen twice — charges a card, sends an email,
    writes to a shared bucket — this belongs in the same durable store as the
    side effect, committed in the same transaction. An in-memory ledger in
    front of an irreversible action is a comfort, not a guarantee.
    """

    def __init__(self, capacity: int = 1024) -> None:
        self._capacity = capacity
        self._lock = threading.Lock()
        # dispatch_id -> (status, body) once finished, or None while running.
        self._entries: OrderedDict[str, tuple[int, bytes] | None] = OrderedDict()
        # Signalled whenever any entry completes, so a concurrent duplicate can
        # wait for the first one instead of racing it.
        self._finished = threading.Condition(self._lock)

    def claim(self, dispatch_id: str, wait_seconds: float) -> tuple[int, bytes] | None:
        """Claim the right to run `dispatch_id`, or return the prior response.

        None means "you run it, and you must call `complete`". A tuple means it
        has already been answered and this is the answer — byte-identical,
        because it is literally the same bytes.

        The in-flight case (a duplicate arriving while the first is still
        running) waits rather than running in parallel. The server is threaded,
        so two copies of one step CAN overlap; letting them would mean two runs
        of the buyer's work for one billed step, and a coin flip over which
        result the orchestrator keeps.
        """
        deadline = time.monotonic() + wait_seconds
        with self._lock:
            while True:
                if dispatch_id in self._entries:
                    stored = self._entries[dispatch_id]
                    if stored is not None:
                        self._entries.move_to_end(dispatch_id)
                        logger.info("dispatch %s replayed from the ledger", dispatch_id)
                        return stored
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        # Still running and we are out of budget. Take it over
                        # rather than answer nothing: a second run is wasteful,
                        # a timeout is a failed step and a 20/100 rating.
                        logger.warning("dispatch %s still in flight — running it again", dispatch_id)
                        return None
                    self._finished.wait(remaining)
                    continue
                self._entries[dispatch_id] = None
                while len(self._entries) > self._capacity:
                    self._entries.popitem(last=False)
                return None

    def complete(self, dispatch_id: str, status: int, body: bytes) -> None:
        """Store what we answered, and wake anyone waiting on it."""
        with self._lock:
            self._entries[dispatch_id] = (status, body)
            self._entries.move_to_end(dispatch_id)
            self._finished.notify_all()

    def abandon(self, dispatch_id: str) -> None:
        """Drop a claim we never completed, so a retry is not stuck waiting.

        Called when the handler raises. The step is not recorded as answered —
        there is no answer — so a retry gets a fresh run, which is what you
        want after a crash mid-step.
        """
        with self._lock:
            if self._entries.get(dispatch_id) is None:
                self._entries.pop(dispatch_id, None)
            self._finished.notify_all()


LEDGER = ReplayLedger()
