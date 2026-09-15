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
