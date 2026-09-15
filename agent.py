#!/usr/bin/env python3
"""The Orizon Agents reference external agent.

    $ pip install pynacl
    $ python3 agent.py

Orizon's orchestrator plans a buyer's workflow, picks an agent for each step,
and POSTs that step as a JSON envelope to the HTTPS endpoint its operator
bound. This file is the other side of that POST: a stdlib HTTP server that
proves the request came from Orizon, works inside the budget it was given, and
answers in the shape the orchestrator accepts. Read it top to bottom.

It is a STARTING POINT, not a framework. Replace `run_step`; keep the rest.

PyNaCl is the only dependency. `stellar-sdk` would give us
`Keypair.verify_message` in one line and cost seven transitive packages and
~12 MB to do it — and every dependency is a chance for your environment to
differ from ours, in a service whose job is to be correct at 3am. The SDK is
itself a thin wrapper over PyNaCl here, so we call PyNaCl directly and write
the two pieces of framing by hand: the SEP-53 message hash and the strkey
decode. Twenty lines between them, and having them visible teaches what a `G…`
address and a Stellar signature actually are.

No secrets live here. This agent verifies signatures and never makes any, so it
holds no private key and there is nothing in this file worth stealing.

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
    PORT                  Set by Render, Fly and Heroku. When present it wins
                          over ORIZON_PORT and switches the default bind
                          address to 0.0.0.0. You never set this by hand.
    ORIZON_PORT           Listen port when PORT is absent. Default 8787.
    ORIZON_HOST           Listen address. Defaults to 0.0.0.0 on a platform
                          (PORT is set) and 127.0.0.1 on a laptop.
    ORIZON_MAX_SKEW       Accepted clock skew on `ts`, seconds. Default 300,
                          which is what the operator doc specifies.
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
# PORT is the PaaS convention: Render, Fly and Heroku inject it and route to
# whatever the process binds. An operator never sets it by hand, so when it is
# present it is the platform speaking and it WINS over our own variable —
# reading only ORIZON_PORT means the platform's port is ignored and every
# dispatch fails as `no_connection` against a service that looks healthy.
#
# Its presence is also how we tell a platform from a laptop, which is what
# picks the bind address. A PaaS routes to the container's public interface, so
# 127.0.0.1 there means unreachable; on a laptop it means the only thing
# exposed is whatever proxy you put in front. Hence 0.0.0.0 when PORT is set.
_PLATFORM_PORT = _env("PORT", "")
LISTEN_PORT = _env_int("PORT", 8787) if _PLATFORM_PORT else _env_int("ORIZON_PORT", 8787)
LISTEN_HOST = _env("ORIZON_HOST", "0.0.0.0" if _PLATFORM_PORT else "127.0.0.1")
MAX_SKEW_SECONDS = _env_int("ORIZON_MAX_SKEW", 300)
# `context` carries every prior step's output, so envelopes are genuinely
# large — but "large" has a number and "unbounded" does not.
MAX_BODY_BYTES = 8 * 1024 * 1024


# ---------------------------------------------------------------------------
# What a `G…` address actually is
# ---------------------------------------------------------------------------


def decode_g_address(address: str) -> bytes:
    """Decode a Stellar `G…` strkey to the 32 raw ed25519 public-key bytes.

    A `G…` address is not a key. It is a 35-byte envelope, base32-encoded:

        byte  0      version byte 0x30 — "ed25519 public key", which is what
                     makes every one of them start with the letter G
        bytes 1..32  the actual 32-byte ed25519 public key
        bytes 33,34  CRC16-XMODEM over the first 33 bytes, little-endian

    35 bytes is 280 bits, which is exactly 56 base32 characters — which is why
    every Stellar address is 56 long and never carries an `=`.

    The checksum is a TYPO guard, not a security control: an adversary computes
    it too. It is checked because the failure it prevents — pinning a corrupted
    signer, then debugging "every signature is invalid" for an afternoon — is
    the one an operator hits on day one. The error quotes nothing: harmless for
    a public address, but this is the shape you would reuse for an `S…` secret.
    """
    if len(address) != 56 or not address.startswith("G"):
        raise ValueError("not a 56-character address starting with G")
    try:
        # Strict about case and length, both of which we want: a lowercased
        # address is a mangled address, not a convenience to absorb.
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
    indistinguishable from one over a transaction envelope, separated only by
    length. Prefixing means a signature made for a message can never be
    replayed as one authorising a payment. `stellar_sdk.Keypair.verify_message`
    is exactly this hash plus an ed25519 verify.
    """
    return hashlib.sha256(SEP53_PREFIX + message.encode("utf-8")).digest()


def dispatch_message(endpoint_url: str, raw_body: bytes) -> str:
    """The exact string Orizon signed for one dispatch.

        orizon-dispatch:v1:{endpoint_url}:{sha256_hex(body)}

    `endpoint_url` is NOT transmitted — not in the body, not in a header. The
    only copy on your side is your own configuration, and that is what makes a
    dispatch signature non-transferable: if the URL rode along in the request,
    a competing operator who received a dispatch could replay the whole signed
    envelope at YOUR endpoint, pass your verification, and have you run — and
    bill — a job Orizon never sent you. Because the URL comes from your config,
    their envelope rebuilds a different message here and fails. Free property,
    nothing to remember.

    `raw_body` is hashed rather than embedded so this stays a bounded, loggable
    string. It must be the bytes AS RECEIVED — see `verify_dispatch`.
    """
    return f"{SIG_VERSION}:{endpoint_url}:{hashlib.sha256(raw_body).hexdigest()}"


# ---------------------------------------------------------------------------
# Verifying that a request really came from Orizon
# ---------------------------------------------------------------------------


class Refused(Exception):
    """A request we will not run. Refusing is cheap: a non-2xx fails the step
    as `error_status`, which is not billed. Running a forged one costs you the
    compute AND puts output you did not author into a buyer's workflow under
    your agent id. When in doubt, refuse."""

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

    `raw_body` MUST be the bytes off the socket, before `json.loads` — this is
    the single most common way to get this wrong. Parse first and re-serialize
    to hash and you are hashing YOUR encoder's output: Python's `json.dumps`
    defaults to `ensure_ascii=True` and `", "` separators, while the
    orchestrator sends `separators=(",", ":"), ensure_ascii=False`. Those agree
    byte for byte on ASCII and diverge on the first accented character, emoji or
    CJK string a buyer types — so the bug passes every test you write, ships,
    and then fails intermittently on the envelopes you cannot reproduce.

    ── THE UNSIGNED-REQUEST POLICY ────────────────────────────────────────────
    Orizon signs a dispatch only when the deployment has a dispatch key
    configured; a deployment without one sends no signature headers at all, and
    that is not an attack. So there are two states and this agent treats them
    differently:

      * ORIZON_SIGNER is PINNED  → a signature is REQUIRED. An unsigned request
        is refused 401. Once you know Orizon holds a key, an unsigned request
        is either a misconfiguration or someone downgrading you to no
        authentication at all, and accepting it makes pinning decorative.

      * ORIZON_SIGNER is EMPTY   → unsigned requests are accepted, each one
        logs a WARNING, and the result is marked UNVERIFIED. This is the
        "not configured yet" state and it is loud on purpose: a silently
        unauthenticated endpoint is how an agent ends up running strangers'
        work. Pin a signer; it is one environment variable.

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
        # against it would make this branch pass. It would also be worthless:
        # an attacker generates a keypair, signs their own forged envelope with
        # it, puts their own public key in X-Orizon-Signer, and every check
        # succeeds — because you asked the sender who to trust. The header says
        # which key Orizon BELIEVES it used, so a rotation shows up as a
        # mismatch instead of a mystery. It is never an input to the decision.
        logger.warning(
            "dispatch carries a signature but ORIZON_SIGNER is not set, so it was NOT "
            "verified. The X-Orizon-Signer header is not a substitute: anyone can set it. "
            "Pin the signer you fetched out of band."
        )
        return UNVERIFIED

    if claimed_signer != PINNED_SIGNER:
        # The one place the header earns its keep: "signed by a key that is
        # not the one I pinned" is a key rotation nine times out of ten.
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

# A dispatch id is hex from `secrets.token_hex(8)`. Pinning the shape lets the
# id be a dict key, a log field, or a filename without becoming an injection
# point. Refused rather than sanitised: sanitising lets two different inputs
# collapse onto one entry, and a collision in the replay ledger returns one
# buyer's output to another.
_DISPATCH_ID_RE = re.compile(r"\A[0-9a-f]{8,64}\Z")


def _text(envelope: dict, key: str) -> str:
    """One string field, or "". The envelope's shape is Orizon's promise; this
    is the boundary at which a promise stops being an assumption."""
    value = envelope.get(key)
    return value if isinstance(value, str) else ""


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

    # The header is OUTSIDE the signed bytes; `dispatch_id` is inside them.
    # Requiring equality stops anyone in the path rewriting the header to split
    # one dispatch into two ledger entries or collapse two into one — they
    # cannot touch the body copy without invalidating the signature, so this
    # drags the header under the signature's protection for free.
    if headers.get(IDEMPOTENCY_HEADER) != dispatch_id:
        raise Refused(400, "Idempotency-Key does not match dispatch_id")

    # The SEP-53 preimage carries no network passphrase, unlike Stellar
    # transaction signing, so a testnet dispatch and a mainnet one are framed
    # identically and `network` is the ONLY thing separating them. Skip this
    # and a testnet envelope — cheap to obtain — replays against a mainnet
    # agent, with real money behind the settlement.
    network = envelope.get("network")
    if network != EXPECTED_NETWORK:
        raise Refused(400, f"network {network!r} is not {EXPECTED_NETWORK!r}")

    # A signature is valid forever; `ts` is what gives it an expiry. 300 s is
    # the documented window — wide, because it absorbs clock skew on both
    # machines. It bounds how long a CAPTURED envelope stays usable; bounding
    # replay is the ledger's job, not this check's.
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
        # Answered, not refused: the fields we read are additive so far, and
        # refusing an envelope we could have served is a failed step and a
        # 20/100 rating we chose for ourselves.
        logger.warning("envelope v%s is newer than v%d — serving it anyway", version, ENVELOPE_VERSION)
    return envelope


# ---------------------------------------------------------------------------
# Replay: the same dispatch_id must produce the same answer, not a second run
# ---------------------------------------------------------------------------


# Orizon retries a dispatch exactly once, and ONLY when the connection never
# established — so in the case it retries, you never ran. But the retry carries
# the SAME `dispatch_id`, which says something more useful than "you may ignore
# this": the id is the orchestrator's unit of work, and answering it twice with
# two different results is a bug.
#
# So the rule is REPLAY, not reject. Returning the stored bytes is correct and
# free; answering an error for a duplicate turns a retry that was meant to
# rescue a failed connection into a failed step.
#
# Bounded, because a `dispatch_id` is attacker-supplied the moment you accept
# unsigned requests. Oldest evicted first, which is safe: a retry follows within
# seconds, so an entry old enough to evict is one no retry will ask for.
#
# IN MEMORY, and therefore LOST ON RESTART. Fine here, because a retry only
# happens when nothing ran. If your agent does something that must not happen
# twice — charges a card, sends mail, writes to a shared bucket — this belongs
# in the same durable store as the side effect, written in the same
# transaction. An in-memory ledger in front of an irreversible action is a
# comfort, not a guarantee.
_ANSWERED: OrderedDict[str, bytes] = OrderedDict()
_ANSWERED_LOCK = threading.Lock()
_ANSWERED_CAPACITY = 1024


def remember(dispatch_id: str, body: bytes) -> None:
    with _ANSWERED_LOCK:
        _ANSWERED[dispatch_id] = body
        _ANSWERED.move_to_end(dispatch_id)
        while len(_ANSWERED) > _ANSWERED_CAPACITY:
            _ANSWERED.popitem(last=False)


def recall(dispatch_id: str) -> bytes | None:
    with _ANSWERED_LOCK:
        return _ANSWERED.get(dispatch_id)


# ---------------------------------------------------------------------------
# The deadline
# ---------------------------------------------------------------------------

# Fallbacks for a `deadline_ms` that is absent or absurd. Read the envelope's
# value rather than hard-coding one — it is inside the signed bytes, so it
# cannot be tampered with in transit, and it can change without telling you.
DEFAULT_DEADLINE_MS = 100_000
MIN_DEADLINE_MS = 1_000
MAX_DEADLINE_MS = 600_000

# How much of the stated budget we are willing to spend on WORK.
#
# Half, and that is not timidity. The orchestrator's clock starts BEFORE it
# connects to you, so DNS, the TCP handshake, the TLS handshake and the upload
# of a large `context` are all already spent by the time your handler runs.
# On a host that sleeps between requests, 30 s of a 100 s budget can be gone
# before the first line of your code executes — and you cannot measure that
# from inside, because the envelope carries a RELATIVE budget, not an absolute
# deadline (it has to: the freshness window is +/-300 s, three times the whole
# budget, so an absolute timestamp could not be converted into a usable one).
#
# What you are buying with the other half is the difference between two very
# different outcomes. Answer late and the step fails as `response_timeout`: it
# is NOT retried (the request was on the wire and may have run, so Orizon will
# not risk billing a buyer twice), it earns 20/100 on-chain, and it is unbilled
# — you did the work, you got nothing, and your rating went down. Answer early
# with a partial result and you are paid and rated for what you delivered.
WORK_FRACTION = 0.5
# Left on top of that for serialising and writing the response body.
RESPONSE_RESERVE_SECONDS = 1.0


def work_deadline(envelope: dict, started: float) -> float:
    """The monotonic instant by which `run_step` must stop working.

    `started` is taken on the first line of the handler; everything after it
    counts, and the orchestrator's clock has been running since before it
    connected.
    """
    raw = envelope.get("deadline_ms")
    if not isinstance(raw, int) or isinstance(raw, bool) or not (MIN_DEADLINE_MS <= raw <= MAX_DEADLINE_MS):
        logger.warning("deadline_ms=%r is unusable — assuming %d ms", raw, DEFAULT_DEADLINE_MS)
        raw = DEFAULT_DEADLINE_MS
    return started + max(0.0, (raw / 1000.0) * WORK_FRACTION - RESPONSE_RESERVE_SECONDS)


# ---------------------------------------------------------------------------
# The work. THIS is the part you replace.
# ---------------------------------------------------------------------------


def _clamp(text: str, limit: int) -> str:
    """Cut `text` to `limit`, marking it so a truncation reads as one.

    Orizon clamps every field it accepts. Clamping here instead means the cut
    happens where you can see it and describe it, rather than arriving in the
    buyer's trace as your prose stopping mid-sentence.
    """
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 14)] + " ...[truncated]"


def esc(value: object) -> str:
    """Any value out of the envelope, made safe to place inside HTML.

    EVERY string in `context` is hostile input: it is what the buyer typed and
    what another operator's agent produced. `html.escape(quote=True)` is the
    whole defence for HTML — and it defends ONLY that context. The same string
    must never be interpolated into a shell command, a SQL statement, a
    filesystem path, or an f-string that becomes one of those.
    """
    if not isinstance(value, str):
        value = json.dumps(value, ensure_ascii=False, default=str)
    return html.escape(value, quote=True)


# How many `context` entries we will look at. A workflow's context grows with
# every prior step, so "iterate the whole thing" is a loop whose length a
# stranger controls.
MAX_CONTEXT_KEYS = 12


def run_step(envelope: dict, deadline: float) -> dict:
    """Do the work, finishing before `deadline`, and return the response parts.

    The reference implementation writes a small HTML report of the step it was
    given — enough to be a real artifact rather than a placeholder — and
    reviews its own output. Replace the body; keep the shape:

      * check the clock between units of work, not only at the top,
      * never let one unit run unbounded (if yours calls a model or an API,
        pass the time left down as ITS timeout),
      * on running out, stop and report what you have.

    A partial result is a delivered result. Being cut off is not.
    """
    intent = _text(envelope, "intent")
    rationale = _text(envelope, "rationale")
    context = envelope.get("context")
    context = context if isinstance(context, dict) else {}

    violations: list[str] = []
    notes: list[str] = []
    sections: list[str] = []
    truncated = False

    if not intent.strip():
        violations.append("the step carried no intent text, so the report describes nothing")

    # One "unit of work" per prior step in the context, with a budget check
    # before each. Real work goes here; the discipline is what matters.
    for index, (key, value) in enumerate(sorted(context.items())[:MAX_CONTEXT_KEYS]):
        if time.monotonic() >= deadline:
            truncated = True
            violations.append(
                f"ran out of time after {index} of {min(len(context), MAX_CONTEXT_KEYS)} inputs; "
                "this report is partial"
            )
            break
        sections.append(f"<section><h2>{esc(key)}</h2><pre>{esc(value)}</pre></section>")
    else:
        if len(context) > MAX_CONTEXT_KEYS:
            notes.append(f"context carried {len(context)} entries; the first {MAX_CONTEXT_KEYS} were read")

    if not context:
        notes.append("no prior step output was supplied, so this step had nothing to build on")
    if not truncated:
        notes.append(f"finished with {deadline - time.monotonic():.1f}s of working time to spare")

    body = "".join(sections) or "<p>No prior step output was supplied.</p>"
    title = _clamp(intent.strip() or "Orizon step report", MAX_TITLE_CHARS)
    document = (
        "<!doctype html><html><head><meta charset='utf-8'>"
        f"<title>{esc(title)}</title></head><body>"
        f"<h1>{esc(title)}</h1>"
        f"<p><strong>Rationale.</strong> {esc(rationale)}</p>"
        f"{body}</body></html>"
    )
    if len(document) > MAX_FILE_CHARS:
        document = document[:MAX_FILE_CHARS]
        violations.append("the generated document exceeded the size limit and was cut")

    summary = _clamp(
        (f"Reported on {len(sections)} prior step(s) for: {intent.strip()}." if intent.strip() else "Produced a step report.")
        + (" Partial: the deadline was reached." if truncated else ""),
        MAX_SUMMARY_CHARS,
    )
    artifact = {
        "title": title,
        "files": [{"path": "report.html", "content": document}],
        "preview_html": document,
    }
    return {"summary": summary, "artifact": artifact, "violations": violations, "notes": notes}


# ---------------------------------------------------------------------------
# The response. READ THIS SECTION EVEN IF YOU SKIM THE REST.
# ---------------------------------------------------------------------------


def _notes(items: list[str]) -> list[str]:
    """A critic list, clamped to what Orizon will accept.

    Clamped here rather than there because Orizon drops a malformed list WHOLE
    — one non-string in `critic_violations` and the entire key disappears,
    taking your rating with it (see `build_response`). Coercing each entry to a
    clamped string means a stray integer costs you one readable note instead.
    """
    return [_clamp(item if isinstance(item, str) else str(item), MAX_NOTE_CHARS) for item in items[:MAX_NOTES]]


def build_response(result: dict) -> bytes:
    """Turn `run_step`'s output into the bytes Orizon will accept, and be rated
    well for.

    ── THE MOST IMPORTANT THING IN THIS FILE ──────────────────────────────────
    The obvious response is `{"summary": "ok"}`. It is accepted. It returns
    200. The buyer's trace reads as a success. And it scores 20 out of 100
    on-chain — the exact score a DEAD ENDPOINT earns — while the step is still
    billed to the buyer.

    The rule on Orizon's side is one line: for an external (untrusted) agent, a
    response carrying neither an `artifact` nor a `critic_violations` LIST has
    proved only that an HTTP handler is alive, so it is rated as a
    non-delivery. Nothing warns you. The failure is invisible until enough of
    those ratings drag your weighted score below the routing floor and the
    planner quietly stops selecting your agent — at which point the evidence is
    months of "successful" steps.

    So this function guarantees two things about every 200 we send:

      1. `artifact` is a real object with real content in it.
      2. `critic_violations` is a LIST — a `list`, specifically, of strings.

    Some details that cost people their rating:

      * `validator_violations` is NOT the key. It is not on Orizon's
        allowlist, so it is dropped before rating ever sees it, and the drop
        is silent. `critic_violations`.
      * A list of anything but strings is dropped WHOLE, not filtered — and a
        dropped list is scored as if you never sent one. `[1, 2]` is worth
        exactly as much as `{"summary": "ok"}`. Hence `_notes`.
      * An EMPTY list is worth +10 and is the honest answer when you checked
        and found nothing. It is a claim, though: do not emit `[]` for work you
        did not review. A populated list costs 3 points per entry (saturating
        at 10 entries), so honest self-reporting is cheap — 2 violations still
        scores 79 against the 20 you get for staying silent.
      * `source` is dropped. Provenance is stamped by Orizon; you cannot claim
        it, and the value that would be worth claiming (`"baked"`, 95/100) is
        specifically why the key is refused.

    And the shape Orizon actually requires: a JSON OBJECT with a non-empty
    string `summary`. No summary, or a body that is not an object, or an
    `artifact` that is not an object, fails the step as `invalid_response`.
    """
    summary = result.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        # A missing summary is `invalid_response` — a failed step. Substituting
        # one is better than failing over a formatting mistake in our own code.
        summary = "Step completed."
    payload: dict[str, object] = {
        "summary": _clamp(summary.strip(), MAX_SUMMARY_CHARS),
        # ALWAYS present, even when empty. This is the line that is worth 50
        # rating points over the naive response.
        "critic_violations": _notes(result.get("violations") or []),
    }
    notes = _notes(result.get("notes") or [])
    if notes:
        payload["critic_notes"] = notes

    artifact = result.get("artifact")
    if isinstance(artifact, dict):
        files = []
        for entry in (artifact.get("files") or [])[:MAX_FILES]:
            if not isinstance(entry, dict):
                continue
            path, content = entry.get("path"), entry.get("content")
            if not isinstance(path, str) or not isinstance(content, str):
                # Orizon drops a half-formed file entry silently; dropping it
                # here keeps the count in our summary honest.
                continue
            files.append({"path": path[:MAX_PATH_CHARS], "content": content[:MAX_FILE_CHARS]})
        built: dict[str, object] = {}
        title = artifact.get("title")
        if isinstance(title, str) and title.strip():
            built["title"] = _clamp(title.strip(), MAX_TITLE_CHARS)
        if files:
            built["files"] = files
        preview = artifact.get("preview_html")
        if isinstance(preview, str):
            built["preview_html"] = preview[:MAX_FILE_CHARS]
        if built:
            payload["artifact"] = built

    # `ensure_ascii=False` keeps the body small and readable; the encoding is
    # declared in our Content-Type and Orizon decodes UTF-8. Note that unlike
    # the REQUEST, where the exact bytes are covered by a signature, nothing
    # about our response is signed, so the serialisation options here are ours
    # to choose.
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    if len(body) > MAX_RESPONSE_BYTES:
        # Over 1 MiB Orizon cuts the stream off UNREAD and fails the step as
        # `oversize_response` — so shedding weight here, in the order of what
        # costs least, is the difference between a rated delivery and nothing.
        # `preview_html` goes first: it duplicates a file we are already
        # sending. The artifact is never dropped entirely, because dropping it
        # is what takes the rating to 20.
        artifact_out = payload.get("artifact")
        if isinstance(artifact_out, dict):
            artifact_out.pop("preview_html", None)
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    return body


# ---------------------------------------------------------------------------
# The server
# ---------------------------------------------------------------------------


class DispatchHandler(BaseHTTPRequestHandler):
    # HTTP/1.1 so connections are reused across a workflow's steps, which is
    # worth several hundred milliseconds of TLS setup out of your budget. It
    # obliges us to send an accurate Content-Length on every response, which
    # `_respond` does; get that wrong and the step fails as `transport_error`.
    protocol_version = "HTTP/1.1"
    server_version = "orizon-example-agent/1"
    # A read timeout on the connection. Without one, a client that opens a
    # socket and sends nothing holds a thread until the process dies — the
    # cheapest denial of service there is against a threaded server.
    timeout = 30

    def log_message(self, fmt: str, *args) -> None:
        """Route access logging through `logging`, WITHOUT the request line.

        The default implementation prints `"POST /dispatch?token=… HTTP/1.1"`
        to stderr. A bound endpoint may legitimately carry a shared secret in
        its query string, and that is the one thing that must never reach a log
        file, a log shipper, or a screenshot. So the path is dropped; the
        outcome is logged where it is produced instead.
        """
        logger.debug("http %s", fmt % args)

    def _respond(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _refuse(self, status: int, reason: str) -> None:
        """Answer a request we will not run.

        The body is for YOU, reading curl output — Orizon never parses a
        non-2xx body, it just records the step as `error_status`. A refused
        step is not billed, which is why refusing is always cheaper than
        guessing.
        """
        logger.warning("refused dispatch: %s", reason)
        self._respond(status, json.dumps({"error": reason}).encode("utf-8"))

    def _read_body(self) -> bytes:
        """The raw request bytes, bounded, exactly as sent.

        These bytes are what the signature covers, so they are read once and
        passed around unmodified. Nothing here decodes, strips or normalises
        them.
        """
        if self.headers.get("Transfer-Encoding", "").lower().strip() == "chunked":
            # `http.server` does not de-chunk, and Orizon always sends a
            # Content-Length. Refusing is honest; silently reading the raw
            # chunk framing as the body would fail the signature check with a
            # message that sends you looking in entirely the wrong place.
            raise Refused(411, "chunked request bodies are not accepted")
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError as e:
            raise Refused(411, "Content-Length is missing or not a number") from e
        if length < 0 or length > MAX_BODY_BYTES:  # checked before allocating anything
            raise Refused(413, f"body of {length} bytes exceeds the {MAX_BODY_BYTES}-byte limit")
        chunks, remaining = [], length
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 65536))
            if not chunk:
                raise Refused(400, "request body ended early")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def do_GET(self) -> None:
        """Liveness, plus the settings that are wrong most often."""
        config = {"ok": True, "endpoint_url": ENDPOINT_URL, "network": EXPECTED_NETWORK,
                  "signature_required": bool(PINNED_SIGNER)}
        self._respond(200, json.dumps(config).encode("utf-8"))

    def do_POST(self) -> None:
        # FIRST LINE OF THE HANDLER. Everything after this counts against the
        # deadline, and the orchestrator's clock has already been running since
        # before it connected.
        started = time.monotonic()
        # No path check, deliberately. The signature is rebuilt from the
        # CONFIGURED ORIZON_ENDPOINT_URL and never from the request, so the path
        # this arrived on is irrelevant to whether we trust it. Gating on
        # `/dispatch` would only turn "I bound the URL without its path" — the
        # most common binding mistake — into a 404 that looks like the service
        # is down rather than misconfigured.
        dispatch_id = None
        try:
            raw_body = self._read_body()

            # Order matters: authenticate before parsing. `json.loads` on an
            # unauthenticated megabyte is work a stranger asked us to do.
            trust = verify_dispatch(self.headers, raw_body)

            try:
                envelope = json.loads(raw_body)
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                raise Refused(400, "body is not valid JSON") from e
            except RecursionError as e:
                # A megabyte of "[[[[..." is ~500k levels deep and defeats
                # CPython's recursive scanner. RecursionError is a RuntimeError,
                # so a `except ValueError` would not hold it and it would take
                # the thread down instead of the request.
                raise Refused(400, "body nesting is too deep") from e

            envelope = check_envelope(envelope, self.headers)
            dispatch_id = envelope["dispatch_id"]
            deadline = work_deadline(envelope, started)

            # Replay before running. Orizon never sends two copies of one
            # dispatch concurrently — it retries only after a connection failed,
            # sequentially — so a plain lookup is enough and a lock around the
            # whole step is not.
            prior = recall(dispatch_id)
            if prior is not None:
                logger.info("dispatch %s replayed from the ledger", dispatch_id)
                self._respond(200, prior)
                return

            body = build_response(run_step(envelope, deadline))
            remember(dispatch_id, body)
            logger.info(
                "dispatch %s (%s) answered in %.2fs, %d bytes",
                dispatch_id,
                trust,
                time.monotonic() - started,
                len(body),
            )
            self._respond(200, body)
        except Refused as e:
            self._refuse(e.status, e.reason)
        except Exception:
            # Our bug, not theirs. A 500 fails the step as `error_status`,
            # which is NOT billed — strictly better for the buyer, and for you,
            # than a 200 carrying an apology: that would be billed AND rated
            # 20/100 for delivering nothing checkable. Never dress a failure up
            # as a delivery.
            logger.exception("dispatch failed")
            self._refuse(500, "internal error")


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

    if not PINNED_SIGNER:
        logger.warning(
            "ORIZON_SIGNER is not set: this agent will run UNVERIFIED dispatches. Fetch "
            "GET /api/stellar/network -> dispatch_signer and pin it before binding a public URL."
        )
    elif not ENDPOINT_URL.startswith("https://"):
        # Not fatal — you may be testing behind a tunnel — but a bound endpoint
        # must be https, and the URL is inside the signed message, so an
        # http/https mismatch between what you bound and what is configured
        # here makes EVERY signature fail with no other symptom.
        logger.warning("ORIZON_ENDPOINT_URL is not https — it must byte-match the URL you bound")

    server = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), DispatchHandler)
    # Threads die with the process; a dispatch in flight at shutdown is a step
    # that fails and is not retried, which is the correct outcome — the
    # alternative is a shutdown that hangs on a 100-second budget.
    server.daemon_threads = True
    logger.info(
        "listening on http://%s:%d — bound endpoint %s, network %s, signature %s",
        LISTEN_HOST,
        LISTEN_PORT,
        ENDPOINT_URL,
        EXPECTED_NETWORK,
        "required" if PINNED_SIGNER else "NOT CHECKED",
    )
    # Plain HTTP on purpose. Orizon requires an HTTPS endpoint, and terminating
    # TLS belongs in front of this process — a reverse proxy, a platform
    # router, a tunnel — not in a file whose job is to be readable. Bind to
    # 127.0.0.1 (the default) and let that proxy be the only thing exposed.
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("shutting down")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
