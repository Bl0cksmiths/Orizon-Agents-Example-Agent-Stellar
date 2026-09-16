"""Tests for the reference agent.

    $ pip install 'pytest>=8,<10'  # dev only — agent.py itself needs only PyNaCl
    $ python3 -m pytest test_agent.py

No network, no fixtures on disk, no secrets. Every keypair is generated inside
the test, so nothing here is worth stealing and nothing here can expire.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import html
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


def strkey(version_byte: int, raw: bytes) -> str:
    """Encode a strkey. The inverse of `agent.decode_g_address`, written
    independently here so the pair is a real round trip rather than one
    function agreeing with itself. The version byte is a parameter so a test
    can build an address of the WRONG kind without a literal seed-shaped
    string sitting in a public repository."""
    payload = bytes([version_byte]) + raw
    return base64.b32encode(payload + struct.pack("<H", binascii.crc_hqx(payload, 0))).decode()


def g_address(verify_key) -> str:
    return strkey(0x30, bytes(verify_key))  # 0x30 is "ed25519 public key"


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


def test_g_address_rejects_junk(key):
    valid = g_address(key.verify_key)
    cases = {
        "empty": "",
        "too short": "GAAA",
        "lowercased": valid.lower(),
        # 0x90 is the ed25519 SECRET SEED version byte: a well-formed strkey of
        # entirely the wrong kind, which the version check is what catches.
        "wrong version byte": strkey(0x90, bytes(32)),
        # One character moved: the CRC16 is what turns a mistyped address into
        # an error here instead of an afternoon of "every signature is invalid".
        "mistyped": valid[:-1] + ("A" if valid[-1] != "A" else "B"),
    }
    for name, bad in cases.items():
        with pytest.raises(ValueError):
            agent.decode_g_address(bad)
            pytest.fail(f"{name} was accepted")


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


# ── The envelope checks ─────────────────────────────────────────────────────


def test_network_mismatch_is_refused():
    with pytest.raises(agent.Refused):
        agent.check_envelope(envelope(network="public"), {"Idempotency-Key": "a1b2c3d4e5f60718"})


def test_stale_ts_is_refused():
    stale = envelope(ts=int(time.time()) - agent.MAX_SKEW_SECONDS - 60)
    with pytest.raises(agent.Refused):
        agent.check_envelope(stale, {"Idempotency-Key": "a1b2c3d4e5f60718"})


def test_rewritten_idempotency_key_is_refused():
    """The header is outside the signed bytes; `dispatch_id` is inside them.
    Pinning one to the other is what puts the header under the signature."""
    with pytest.raises(agent.Refused):
        agent.check_envelope(envelope(), {"Idempotency-Key": "something-else"})


@pytest.mark.parametrize("bad", [None, "", "NOT-HEX", "../../etc/passwd", 17])
def test_malformed_dispatch_id_is_refused(bad):
    with pytest.raises(agent.Refused):
        agent.check_envelope(envelope(dispatch_id=bad), {"Idempotency-Key": bad})


def test_a_newer_envelope_version_is_served_not_refused():
    # Refusing an envelope we could have served is a failed step we chose.
    body = envelope(v=99)
    assert agent.check_envelope(body, {"Idempotency-Key": body["dispatch_id"]}) is body


# ── The deadline ────────────────────────────────────────────────────────────


def test_work_deadline_leaves_headroom():
    deadline = agent.work_deadline(envelope(deadline_ms=100_000), started=1_000.0)
    # Half the stated budget, less the reserve for writing the response.
    assert deadline == pytest.approx(1_000.0 + 100 * agent.WORK_FRACTION - agent.RESPONSE_RESERVE_SECONDS)


def test_an_absurd_deadline_falls_back_to_the_default():
    assert agent.work_deadline(envelope(deadline_ms="soon"), 0.0) == pytest.approx(
        agent.DEFAULT_DEADLINE_MS / 1000 * agent.WORK_FRACTION - agent.RESPONSE_RESERVE_SECONDS
    )


def test_run_step_returns_a_partial_result_when_out_of_time():
    """Being cut off is a `response_timeout`: unbilled, never retried, 20/100.
    Stopping early is a delivery."""
    body = envelope(context={"a": "1", "b": "2", "c": "3"})
    result = agent.run_step(body, deadline=time.monotonic() - 1)  # already gone
    assert result["artifact"]["files"], "a partial result is still an artifact"
    assert any("ran out of time" in v for v in result["violations"])


# ── The response contract ───────────────────────────────────────────────────


def orizon_parse(raw: object) -> dict | None:
    """What Orizon keeps of our response.

    A condensed `app.agents.workers.external_contract.parse_operator_output`:
    an allowlist, not a filter. None means the step is REFUSED
    (`invalid_response`); everything not named here is dropped silently.
    """
    if not isinstance(raw, dict):
        return None
    summary = raw.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        return None
    out: dict = {"summary": summary[: agent.MAX_SUMMARY_CHARS]}
    artifact = raw.get("artifact")
    if artifact is not None:
        if not isinstance(artifact, dict):
            return None  # `artifact_not_an_object` — a refusal, not a drop
        kept = {k: v for k, v in artifact.items() if k in ("title", "files", "preview_html")}
        if kept:
            out["artifact"] = kept
    for key in ("critic_violations", "critic_notes"):
        value = raw.get(key)
        # Dropped WHOLE when malformed — never filtered item by item.
        if isinstance(value, list) and all(isinstance(i, str) for i in value):
            out[key] = value[: agent.MAX_NOTES]
    return out


def synthetic_rating(output: dict | None) -> int:
    """`app.services.reputation_svc.synthetic_rating`, untrusted branch."""
    if not output:
        return 20
    if not (output.get("artifact") or isinstance(output.get("critic_violations"), list)):
        return 20  # an acknowledgement is worth what a dead endpoint is worth
    rating = 70
    if output.get("artifact"):
        rating += 15
    violations = output.get("critic_violations")
    if isinstance(violations, list):
        rating += 10 if not violations else -3 * min(len(violations), 10)
    return max(0, min(100, rating))


def test_the_naive_response_scores_the_same_as_a_dead_endpoint():
    """The failure this whole file exists to stop. It is ACCEPTED — and rated
    identically to never answering at all, while still being billed."""
    assert orizon_parse({"summary": "ok"}) is not None
    assert synthetic_rating(orizon_parse({"summary": "ok"})) == 20


def test_our_response_survives_the_allowlist_and_scores_well():
    body = envelope()
    kept = orizon_parse(json.loads(agent.build_response(agent.run_step(body, time.monotonic() + 30))))
    assert kept is not None, "the step must not be refused"
    assert kept["artifact"]["files"], "the artifact must survive the allowlist"
    assert isinstance(kept["critic_violations"], list)
    assert synthetic_rating(kept) == 95


def test_a_partial_result_still_beats_a_dead_endpoint():
    partial = agent.run_step(envelope(), deadline=time.monotonic() - 1)
    kept = orizon_parse(json.loads(agent.build_response(partial)))
    assert synthetic_rating(kept) > 20


def test_critic_violations_are_always_a_list_of_strings():
    """A list containing a non-string is dropped WHOLE by Orizon, which scores
    as if we had sent none — so non-strings are coerced, never passed on."""
    payload = json.loads(agent.build_response({"summary": "done", "violations": [1, None, "real"]}))
    assert payload["critic_violations"] == ["1", "None", "real"]
    assert synthetic_rating(orizon_parse(payload)) > 20


def test_a_missing_summary_is_substituted_not_sent_empty():
    # No summary is `invalid_response` — a failed step over our own formatting.
    assert json.loads(agent.build_response({}))["summary"].strip()


def test_an_oversize_response_is_shed_rather_than_cut_off():
    huge = "x" * (agent.MAX_FILE_CHARS)
    body = agent.build_response(
        {
            "summary": "done",
            "violations": [],
            "artifact": {"title": "big", "files": [{"path": f"f{i}.txt", "content": huge} for i in range(24)],
                         "preview_html": huge},
        }
    )
    payload = json.loads(body)
    assert "preview_html" not in payload["artifact"], "the duplicate payload is shed first"
    assert payload["artifact"]["files"], "the artifact is never dropped — that is what scores 20"


def test_hostile_context_is_escaped_into_the_artifact():
    """`context` is what the buyer typed and what another operator's agent
    produced. It reaches the buyer's viewer as HTML, so it arrives escaped —
    the markup survives as visible text and never as markup."""
    hostile = "<img src=x onerror=alert(1)><script>fetch('//evil')</script>"
    document = agent.run_step(envelope(context={"prior": hostile}), time.monotonic() + 30)
    document = document["artifact"]["files"][0]["content"]
    assert hostile not in document, "never verbatim"
    assert "<script>" not in document and "<img" not in document, "no tag survives as a tag"
    assert html.escape(hostile, quote=True) in document, "it survives as text"


# ── End to end, over a real socket ──────────────────────────────────────────


@pytest.fixture
def server(pinned):
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), agent.DispatchHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


def post(base: str, key: SigningKey, body: dict | None = None, path: str = "/dispatch", sign_url: str = OUR_URL):
    body = body if body is not None else envelope()
    raw = serialize(body)
    request = urllib.request.Request(
        base + path, data=raw, method="POST",
        headers=headers_for(key, sign_url, raw, body["dispatch_id"]),
    )
    try:
        with urllib.request.urlopen(request) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def test_a_signed_dispatch_is_served(server, pinned):
    status, body = post(server, pinned)
    assert status == 200
    assert synthetic_rating(orizon_parse(json.loads(body))) == 95


def test_any_path_is_accepted(server, pinned):
    """The signature is rebuilt from configuration, so the path is irrelevant —
    and gating on it turns a common binding mistake into a confusing 404."""
    assert post(server, pinned, path="/")[0] == 200


def test_a_replayed_dispatch_returns_the_prior_bytes_without_rerunning(server, pinned, monkeypatch):
    runs = []
    original = agent.run_step
    monkeypatch.setattr(agent, "run_step", lambda *a, **kw: (runs.append(1), original(*a, **kw))[1])

    first = post(server, pinned)
    second = post(server, pinned)  # same dispatch_id: Orizon's connection-failure retry
    assert first == second, "a retry must get the identical prior response"
    assert len(runs) == 1, "the step must not run twice"


def test_a_tight_deadline_still_answers_in_time(server, pinned):
    status, body = post(server, pinned, envelope(deadline_ms=agent.MIN_DEADLINE_MS))
    payload = json.loads(body)
    assert status == 200
    assert any("ran out of time" in v for v in payload["critic_violations"])
    assert synthetic_rating(orizon_parse(payload)) > 20


def test_a_forged_dispatch_is_refused_over_the_socket(server):
    assert post(server, SigningKey.generate())[0] == 401


def test_a_body_that_is_not_json_is_refused(server, pinned):
    raw = b"{not json"
    request = urllib.request.Request(
        server + "/dispatch", data=raw, method="POST",
        headers=headers_for(pinned, OUR_URL, raw, "a1b2c3d4e5f60718"),
    )
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(request)
    assert exc.value.code == 400
