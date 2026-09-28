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
import http.client
import json
import os
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

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
    agent._FAULT_COUNTS.clear()
    yield
    agent._ANSWERED.clear()
    agent._FAULT_COUNTS.clear()


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


# ── The golden: what an operator's agent does when nothing is switched on ────
#
# Pinned byte for byte, so anything added alongside the handler — the
# fault-injection mode below is the reason this exists — is proven to change
# nothing when it is off. Written against the code BEFORE that mode existed.

GOLDEN_REPORT = (
    "<!doctype html><html><head><meta charset='utf-8'><title>Design the pricing page</title></head>"
    "<body><h1>Design the pricing page</h1><p><strong>Rationale.</strong> the planner routed the UI step here</p>"
    "<section><h2>brief</h2><pre>café</pre></section></body></html>"
)
GOLDEN_DISPATCH = {
    "summary": "Reported on 1 prior step(s): Design the pricing page",
    "critic_violations": [],
    "critic_notes": ["1 context entries supplied, 1 read"],
    "artifact": {
        "title": "Design the pricing page",
        "files": [{"path": "report.html", "content": GOLDEN_REPORT}],
        "preview_html": GOLDEN_REPORT,
    },
}


def exchange(base: str, method: str, raw: bytes | None = None, headers: dict | None = None, timeout: float = 10):
    """One request over a fresh connection: (status, headers, body). Lower
    level than `post` because the golden pins the response headers too."""
    host, port = base.removeprefix("http://").split(":")
    connection = http.client.HTTPConnection(host, int(port), timeout=timeout)
    try:
        connection.request(method, "/dispatch", body=raw, headers=headers or {})
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


def test_golden_dispatch_is_byte_identical(server, pinned):
    body = envelope(context={"brief": "café"})
    raw = serialize(body)
    status, headers, answer = exchange(server, "POST", raw, headers_for(pinned, OUR_URL, raw, body["dispatch_id"]))
    assert status == 200
    assert answer == json.dumps(GOLDEN_DISPATCH, ensure_ascii=False).encode("utf-8")
    # Date and Server vary by clock and interpreter; the rest must not grow.
    assert set(headers) == {"Server", "Date", "Content-Type", "Content-Length"}
    assert headers["Content-Type"] == "application/json; charset=utf-8"


def test_golden_health_is_byte_identical(server, pinned):
    status, headers, answer = exchange(server, "GET")
    assert status == 200
    assert answer == json.dumps(
        {"ok": True, "endpoint_url": OUR_URL, "network": "testnet", "signature_required": True}
    ).encode("utf-8")
    assert set(headers) == {"Server", "Date", "Content-Type", "Content-Length"}


# ── Fault injection: the configuration contract ─────────────────────────────


@pytest.fixture
def fault_env(key) -> dict:
    """The smallest environment fault injection agrees to start in."""
    return {"ORIZON_SIGNER": g_address(key.verify_key), "ORIZON_NETWORK": "testnet"}


def test_fault_injection_is_off_by_default(fault_env):
    assert agent.load_fault_config(fault_env) is None
    assert agent.load_fault_config({}) is None
    assert agent.FAULT is None, "importing the agent must never switch a fault on"


@pytest.mark.parametrize(
    ("mode", "scope", "label"),
    [
        ("hang_after:0", "", "hang_after:0 scope=process"),
        ("hang_after:3", "intent", "hang_after:3 scope=intent"),
        ("error_after:2", "process", "error_after:2 scope=process"),
        ("delay_ms:1500", "", "delay_ms:1500"),
        ("  delay_ms:1  ", "", "delay_ms:1"),
    ],
)
def test_valid_fault_modes_parse(fault_env, mode, scope, label):
    config = agent.load_fault_config({**fault_env, "FAULT_MODE": mode, "FAULT_SCOPE": scope})
    assert config is not None and config.label == label


@pytest.mark.parametrize(
    ("overrides", "named"),
    [
        ({"FAULT_MODE": "hang"}, "FAULT_MODE"),
        ({"FAULT_MODE": "hang_after"}, "FAULT_MODE"),
        ({"FAULT_MODE": "hang_after:"}, "FAULT_MODE"),
        ({"FAULT_MODE": "hang_after:-1"}, "FAULT_MODE"),
        ({"FAULT_MODE": "hang_after:+1"}, "FAULT_MODE"),
        ({"FAULT_MODE": "hang_after:1.5"}, "FAULT_MODE"),
        ({"FAULT_MODE": "hang_after:01"}, "FAULT_MODE"),
        ({"FAULT_MODE": "hang_after:9999999"}, "FAULT_MODE"),
        ({"FAULT_MODE": "hang_after:٣"}, "FAULT_MODE"),  # a digit to int(), not to us
        ({"FAULT_MODE": "Hang_After:1"}, "FAULT_MODE"),
        ({"FAULT_MODE": "crash_after:1"}, "FAULT_MODE"),
        ({"FAULT_MODE": "delay_ms:0"}, "FAULT_MODE"),
        ({"FAULT_MODE": "delay_ms:600001"}, "FAULT_MODE"),
        ({"FAULT_MODE": "error_after:x"}, "FAULT_MODE"),
        ({"FAULT_MODE": "hang_after:1", "FAULT_SCOPE": "task"}, "FAULT_SCOPE"),
        ({"FAULT_MODE": "delay_ms:10", "FAULT_SCOPE": "process"}, "FAULT_SCOPE"),
        ({"FAULT_SCOPE": "process"}, "FAULT_SCOPE"),
        ({"FAULT_MODE": "hang_after:1", "ORIZON_SIGNER": ""}, "ORIZON_SIGNER"),
        ({"FAULT_MODE": "hang_after:1", "ORIZON_SIGNER": "GNOTANADDRESS"}, "ORIZON_SIGNER"),
        ({"FAULT_MODE": "hang_after:1", "ORIZON_NETWORK": "public"}, "ORIZON_NETWORK"),
    ],
)
def test_an_invalid_fault_setting_is_refused_by_name(fault_env, overrides, named):
    with pytest.raises(agent.FaultConfigError) as exc:
        agent.load_fault_config({**fault_env, **overrides})
    assert str(exc.value).startswith(named), f"the message must lead with {named}: {exc.value}"


def start_agent(env: dict) -> subprocess.CompletedProcess:
    """`python3 agent.py` as a deploy would run it, stopped at 5 s if it did
    not refuse. Port 0, so a start that wrongly succeeds binds nothing fixed."""
    return subprocess.run(
        [sys.executable, str(Path(agent.__file__))],
        env={"PATH": os.environ.get("PATH", ""), "ORIZON_PORT": "0", **env},
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )


@pytest.mark.parametrize(
    ("overrides", "named"),
    [
        ({"FAULT_MODE": "hang_after:soon"}, "FAULT_MODE"),
        ({"FAULT_MODE": "error_after:1", "FAULT_SCOPE": "everywhere"}, "FAULT_SCOPE"),
        ({"FAULT_MODE": "hang_after:1", "ORIZON_SIGNER": ""}, "ORIZON_SIGNER"),
    ],
)
def test_an_invalid_fault_setting_refuses_to_start(fault_env, overrides, named):
    started = start_agent({**fault_env, **overrides})
    assert started.returncode == 2
    assert f"refusing to start: {named}" in started.stderr
    assert "listening on" not in started.stderr, "it must refuse before it binds"


def test_an_active_fault_mode_announces_itself_before_listening(fault_env):
    process = subprocess.Popen(
        [sys.executable, str(Path(agent.__file__))],
        env={"PATH": os.environ.get("PATH", ""), "ORIZON_PORT": "0", **fault_env, "FAULT_MODE": "hang_after:2"},
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        lines = []
        for line in process.stderr:
            lines.append(line)
            if "listening on" in line:
                break
        announced = [i for i, line in enumerate(lines) if "FAULT INJECTION ACTIVE (hang_after:2 scope=process)" in line]
        assert announced and announced[0] < len(lines) - 1, "".join(lines)
        assert "WARNING" in lines[announced[0]]
    finally:
        process.kill()
        process.wait(timeout=5)


# ── Fault injection: the counter ────────────────────────────────────────────


def fault_on(monkeypatch, mode: str, scope: str = "process") -> None:
    kind, _, value = mode.partition(":")
    monkeypatch.setattr(agent, "FAULT", agent.FaultConfig(kind, int(value), scope))


def test_hang_after_serves_n_then_holds_past_the_deadline(monkeypatch):
    fault_on(monkeypatch, "hang_after:2")
    actions = [agent.fault_action(envelope(), agent.VERIFIED) for _ in range(4)]
    hold = agent.DEFAULT_DEADLINE_MS / 1000 + agent.FAULT_HOLD_MARGIN_SECONDS
    assert actions == [None, None, ("hang", hold), ("hang", hold)]


def test_error_after_serves_n_then_errors(monkeypatch):
    fault_on(monkeypatch, "error_after:1")
    assert [agent.fault_action(envelope(), agent.VERIFIED) for _ in range(3)] == [None, ("error", 0.0), ("error", 0.0)]


def test_delay_ms_delays_every_dispatch_and_counts_nothing(monkeypatch):
    fault_on(monkeypatch, "delay_ms:250")
    assert [agent.fault_action(envelope(), agent.VERIFIED) for _ in range(3)] == [("delay", 0.25)] * 3
    assert not agent._FAULT_COUNTS


def test_an_unverified_dispatch_never_advances_the_counter(monkeypatch):
    fault_on(monkeypatch, "error_after:0")
    assert agent.fault_action(envelope(), agent.UNVERIFIED) is None
    assert not agent._FAULT_COUNTS


def test_intent_scope_counts_each_workflow_separately(monkeypatch):
    """The orchestrator repeats the plan's intent on every step of one
    workflow, so hang_after:1 under this scope means "the second time THIS
    workflow reaches me", whatever other workflows did first."""
    fault_on(monkeypatch, "hang_after:1", scope="intent")
    first, second = envelope(intent="appraise listing A"), envelope(intent="appraise listing B")
    assert agent.fault_action(first, agent.VERIFIED) is None
    assert agent.fault_action(second, agent.VERIFIED) is None, "another workflow's dispatch must not count"
    assert agent.fault_action(first, agent.VERIFIED)[0] == "hang"
    assert agent.fault_action(second, agent.VERIFIED)[0] == "hang"


def test_process_scope_counts_every_workflow_together(monkeypatch):
    fault_on(monkeypatch, "hang_after:1")
    assert agent.fault_action(envelope(intent="appraise listing A"), agent.VERIFIED) is None
    assert agent.fault_action(envelope(intent="appraise listing B"), agent.VERIFIED)[0] == "hang"


def test_the_counter_is_exact_under_concurrency(monkeypatch):
    """ThreadingHTTPServer answers each dispatch on its own thread. Exactly N
    must be served — a read-then-write race serves N+k and the step that was
    meant to hang delivers instead."""
    fault_on(monkeypatch, "error_after:1000")
    threads, per_thread = 16, 400
    same = envelope()
    barrier = threading.Barrier(threads)
    results: list = []
    lock = threading.Lock()

    def dispatch_many():
        barrier.wait()
        mine = [agent.fault_action(same, agent.VERIFIED) for _ in range(per_thread)]
        with lock:
            results.extend(mine)

    previous = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)  # switch threads as often as CPython will, to give a race every chance
    try:
        workers = [threading.Thread(target=dispatch_many) for _ in range(threads)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()
    finally:
        sys.setswitchinterval(previous)
    assert results.count(None) == 1000
    assert len(results) == threads * per_thread
    assert agent._FAULT_COUNTS["process"] == threads * per_thread


def test_the_counter_hands_out_distinct_ordinals_under_concurrency():
    threads, per_thread = 16, 5000
    barrier = threading.Barrier(threads)
    seen: list[int] = []
    lock = threading.Lock()

    def count_many():
        barrier.wait()
        mine = [agent.count_dispatch("process") for _ in range(per_thread)]
        with lock:
            seen.extend(mine)

    previous = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        workers = [threading.Thread(target=count_many) for _ in range(threads)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()
    finally:
        sys.setswitchinterval(previous)
    assert sorted(seen) == list(range(1, threads * per_thread + 1))


def test_the_hold_is_bounded_by_the_clamped_budget():
    margin = agent.FAULT_HOLD_MARGIN_SECONDS
    assert agent.fault_hold_seconds(envelope(deadline_ms=100_000)) == 100 + margin
    # Past the orchestrator's 100 s deadline, which is measured from before it connected.
    assert agent.fault_hold_seconds(envelope(deadline_ms=100_000)) > 100
    # An absurd or hostile budget cannot turn the hold into forever.
    assert agent.fault_hold_seconds(envelope(deadline_ms=10**12)) == agent.DEFAULT_DEADLINE_MS / 1000 + margin
    assert agent.fault_hold_seconds(envelope(deadline_ms="forever")) == agent.DEFAULT_DEADLINE_MS / 1000 + margin
    longest = agent.MAX_DEADLINE_MS / 1000 + margin
    assert agent.fault_hold_seconds(envelope(deadline_ms=agent.MAX_DEADLINE_MS)) == longest
    assert 0 < margin < 60


# ── Fault injection: over a real socket ─────────────────────────────────────


def signed(key: SigningKey, dispatch_id: str, **overrides) -> tuple[bytes, dict]:
    body = envelope(dispatch_id=dispatch_id, **overrides)
    raw = serialize(body)
    return raw, headers_for(key, OUR_URL, raw, dispatch_id)


@pytest.fixture
def runs(monkeypatch) -> list:
    """How many times the step itself actually ran."""
    calls: list = []
    original = agent.run_step
    monkeypatch.setattr(agent, "run_step", lambda *a, **kw: (calls.append(1), original(*a, **kw))[1])
    return calls


def test_hang_after_holds_then_hangs_up_unanswered(server, pinned, monkeypatch, runs):
    fault_on(monkeypatch, "hang_after:1")
    monkeypatch.setattr(agent, "FAULT_HOLD_MARGIN_SECONDS", 0.3)
    # deadline_ms=1000 → a 1.3 s hold, so the test runs in seconds, not minutes.
    status, headers, _ = exchange(server, "POST", *signed(pinned, "aaaa000000000001", deadline_ms=1000))
    assert status == 200 and headers[agent.FAULT_HEADER] == "hang_after:1 scope=process"

    # It HOLDS: a client that gives up first gets nothing at all.
    with pytest.raises(TimeoutError):
        exchange(server, "POST", *signed(pinned, "aaaa000000000002", deadline_ms=1000), timeout=0.6)

    # And the hold is BOUNDED: a patient client sees the connection closed,
    # with no status line, once the hold is up — not a thread held forever.
    began = time.monotonic()
    with pytest.raises(http.client.RemoteDisconnected):
        exchange(server, "POST", *signed(pinned, "aaaa000000000003", deadline_ms=1000), timeout=5)
    assert 1.2 <= time.monotonic() - began < 4
    assert len(runs) == 1, "a hung dispatch must never run the step"


def test_error_after_answers_503_after_n(server, pinned, monkeypatch, runs):
    fault_on(monkeypatch, "error_after:1")
    assert exchange(server, "POST", *signed(pinned, "bbbb000000000001"))[0] == 200
    status, headers, answer = exchange(server, "POST", *signed(pinned, "bbbb000000000002"))
    assert status == 503
    assert json.loads(answer) == {"error": "fault injection: error_after:1 scope=process"}
    assert headers[agent.FAULT_HEADER] == "error_after:1 scope=process"
    assert len(runs) == 1


def test_delay_ms_answers_correctly_after_the_delay(server, pinned, monkeypatch):
    fault_on(monkeypatch, "delay_ms:400")
    began = time.monotonic()
    status, headers, answer = exchange(server, "POST", *signed(pinned, "cccc000000000001"))
    assert time.monotonic() - began >= 0.4
    assert status == 200 and headers[agent.FAULT_HEADER] == "delay_ms:400"
    assert synthetic_rating(orizon_parse(json.loads(answer))) == 95


def test_unauthenticated_and_invalid_requests_never_advance_the_counter(server, pinned, monkeypatch):
    fault_on(monkeypatch, "error_after:1")
    stranger = SigningKey.generate()
    for i in range(3):  # forged: the attacker's own key, announced in the header
        assert exchange(server, "POST", *signed(stranger, f"dddd00000000000{i}"))[0] == 401
    for i in range(2):  # unsigned
        raw = serialize(envelope(dispatch_id=f"eeee00000000000{i}"))
        assert exchange(server, "POST", raw, {"Idempotency-Key": f"eeee00000000000{i}"})[0] == 401
    # Signed by the real key but a refused envelope: authentic, not a dispatch.
    assert exchange(server, "POST", *signed(pinned, "ffff000000000001", network="public"))[0] == 400
    assert exchange(server, "GET")[0] == 200
    assert not agent._FAULT_COUNTS, "nothing above may have been counted"

    assert exchange(server, "POST", *signed(pinned, "abab000000000001"))[0] == 200, "still the first good dispatch"
    assert exchange(server, "POST", *signed(pinned, "abab000000000002"))[0] == 503


def test_a_replayed_dispatch_is_not_counted_twice(server, pinned, monkeypatch):
    """Orizon's one retry reuses the dispatch_id. It is the same unit of work,
    so it replays from the ledger and must not use up a second good answer."""
    fault_on(monkeypatch, "error_after:1")
    first = exchange(server, "POST", *signed(pinned, "acac000000000001"))
    again = exchange(server, "POST", *signed(pinned, "acac000000000001"))
    assert first[0] == again[0] == 200 and first[2] == again[2]
    assert exchange(server, "POST", *signed(pinned, "acac000000000002"))[0] == 503


def test_the_health_check_reports_an_active_fault_mode(server, pinned, monkeypatch):
    fault_on(monkeypatch, "hang_after:2", scope="intent")
    status, headers, answer = exchange(server, "GET")
    assert status == 200
    assert json.loads(answer)["fault_injection"] == "hang_after:2 scope=intent"
    assert headers[agent.FAULT_HEADER] == "hang_after:2 scope=intent"
