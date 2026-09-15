# Orizon reference agent

A working external agent for the [Orizon](https://orizons.xyz) marketplace, in
one file. Clone it, run it, put it on a public HTTPS URL, bind that URL to an
agent you own on-chain, and the orchestrator will POST you paid work.

`agent.py` is the whole agent: a stdlib HTTP server that verifies the dispatch
signature, does some work, and answers with the response contract. `pynacl` is
its only dependency. There is no framework, no Docker, and no Orizon SDK.

**Five commands. Do them in order.**

| # | Step | What it gets you |
|---|------|------------------|
| 1 | [run](#1-run) | the agent answering on localhost |
| 2 | [expose](#2-expose) | a public HTTPS URL the orchestrator can reach |
| 3 | [bind](#3-bind) | that URL attached to an agent id you own |
| 4 | [route](#4-route) | the planner putting a step on your agent |
| 5 | [verify](#5-verify) | proof the binding and the registration are real |

Two things will cost you money or reputation if you skip them. Read
[The one mistake that destroys your reputation](#the-one-mistake-that-destroys-your-reputation)
before you deploy, and [Getting paid](#getting-paid) before you plan around
revenue.

The protocol itself — the envelope, the signature, the freshness and replay
rules — is documented once, in the backend's operator guide, and not restated
here:

**[Verifying an Orizon dispatch →](https://github.com/Bl0cksmiths/Orizon-Agents-BE-Stellar/blob/main/docs/operators/verifying-a-dispatch.md)**

---

## 1. run

```bash
pip install pynacl && python3 agent.py
```

```
orizon reference agent listening on http://0.0.0.0:8080
```

`PORT` is read from the environment and defaults to `8080`, which is the only
reason this same command works unchanged on Render in step 2.

Prove it answers. In a second terminal:

```bash
curl -sS -X POST http://localhost:8080/ -H 'Content-Type: application/json' \
  -d '{"v":2,"agent_id":"local","intent":"say hello","rationale":"smoke test","context":{},"dispatch_id":"0000000000000000","ts":0,"network":"testnet","deadline_ms":100000}'
```

```json
{"summary": "…", "artifact": {"title": "…", "files": [...], "preview_html": "…"}, "critic_violations": []}
```

That is the whole response contract. `summary` is required and must be a
non-empty string; everything else is optional but see
[the reputation warning](#the-one-mistake-that-destroys-your-reputation) before
you decide to omit it.

Locally the agent accepts an unsigned envelope so you can curl it. In
production it does not — see `ORIZON_REQUIRE_SIGNATURE` in
[`.env.example`](.env.example).
