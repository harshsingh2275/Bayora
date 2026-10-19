# Bayora: Prompts and Commit Statements

How to use: open a **new conversation per prompt** (never reuse a long thread), paste the prompt as is, let the agent finish, review the report, then commit with the given message and tag.

Naming: **P** = build prompt, **S** = security audit/test prompt (always a **separate fresh session**), **X** = extra or stretch prompt, **H** = hotfix or help prompt.
Every build prompt begins with the same context line, so you can also reuse it manually:

> CONTEXT: Read `AGENTS.md`, `docs/architecture.md`, `docs/task.md` and `docs/prd.md` first. Follow `AGENTS.md` strictly. Do not start coding until you have read them.

---

## P-00: Kickoff (no code)  [Day 1, first thing]

```
CONTEXT: Read AGENTS.md, docs/architecture.md, docs/task.md and docs/prd.md fully.
Do NOT write any code or create any files yet.
Reply with: (1) the project in your own words (max 10 lines), (2) the list of tasks T00-T14 with the order you will follow, (3) anything in the docs that is unclear, contradictory, risky or impossible on a standard Linux host (be specific, cite sections), (4) the third-party items from architecture §15 you plan to verify first and how.
Wait for my approval.
```
Commit: none.

---

## P-01: Bootstrap + compose skeleton + hardening (T00 + T01)

```
CONTEXT: Read AGENTS.md, docs/architecture.md (§2, §3, §4, §13, §14) and docs/task.md (T00, T01).
Do T00 and T01 together:
1. Create the repo layout (§13), .gitignore, .env.example, Makefile (all targets from §13 must exist; not-yet-built ones print "not implemented yet"), scripts/gen-secrets.sh, scripts/sync-agents.sh. Copy docs/agents.md to AGENTS.md.
2. gen-secrets.sh exactly as specified in T00 (tokens, SHA-256 files, Ed25519 keypair via OpenSSL, modes 0700 dir / 0644 files, no overwrite without --force, never print secret values).
3. docker-compose.yml with all seven services and five networks per §2. Apply the hardening baseline (§3) to every custom service. Secrets and volumes per §4. Services may be minimal stubs exposing only a health endpoint; web serves a placeholder page and proxies only /api/* to the gateway (404 for /v1/*).
4. Healthchecks on every service using the Python standard library.
5. Comment every exception in the compose file.
Acceptance: docker compose up -d is all healthy; docker compose config shows internal networks, non-root users, cap_drop ALL, limits; from `docker compose exec red` the names blue, model, logger do not resolve; `curl localhost:8088/v1/red/work` returns 404; secrets are not tracked by git.
Show real command output. End with the report format from AGENTS.md.
```
Commit: `chore: bootstrap repo, secrets generation and hardened compose skeleton` · Tag: `t01-done`
Then run **S-01** before moving on.

---

## P-02: Model service (T02)

```
CONTEXT: Read AGENTS.md, docs/architecture.md (§9, §15) and docs/task.md (T02).
Add the model service. Before writing config, VERIFY against the real image and its --help/README (do not rely on memory): the image name and a pinned tag that runs on this CPU architecture, the flags (--parallel, -c, threads), the request field names for slot pinning and prompt caching, whether the chat-completions endpoint accepts them or the native /completion endpoint is required (then apply the model's chat template manually), whether a slot erase endpoint exists, whether the image has a shell or curl for healthchecks.
Write all findings, each with how you verified it, into docs/verified-notes.md.
Then: add the model service on model-net only (hardened per §3, resolve any non-root or read-only problem by testing and record the final choice), mount data/models read-only, MODEL_FILE from env, --parallel 2, CPU only, resource limits from env. Add scripts/model-smoke.sh that sends one chat request from a throwaway container attached to model-net and prints the reply and latency.
The human has already placed the GGUF file in data/models/ (see docs/manual-actions.md M-05).
Acceptance: model healthy; smoke script returns a sensible reply; verified-notes.md complete. Report with evidence.
```
Commit: `feat: add llama.cpp model service and record verified server behavior` · Tag: `t02-done`

---

## P-03: Gateway core (T03)  [HEAVY: use the strongest Claude model]

```
CONTEXT: Read AGENTS.md, docs/architecture.md (§2, §5 tenant endpoints, §7 model request, §9, §3) and docs/task.md (T03). Use docs/verified-notes.md for model server behavior.
Implement the gateway core (FastAPI):
- Token auth for red and blue (hash comparison with hmac.compare_digest, hashes from file secrets), operator token for admin routes, role checks.
- Pydantic v2 request models with extra="forbid" for every endpoint in §5 that exists at this stage; implement /v1/{role}/work, probes, and the model client. Run endpoints (commit, defense, attack, done, reports) may return 501 for now.
- The gateway builds the model request itself: fixed system prompt, temperature 0, max_tokens capped (1..128 for probes), slot parameters chosen from the current cache mode (isolated: red slot 0, blue slot 1; shared: no pinning) using the VERIFIED field names. Never forward client-supplied model parameters.
- Strip every non-whitelisted field from model responses (timings, usage, cache and slot info). Tenants get only {"text": ...}.
- In-memory rate limiting per tenant (env-configurable).
- SQLite schema via aiosqlite: runs, commitments, bundles, attacks, settings (cache mode). Migrations are just idempotent CREATE TABLE IF NOT EXISTS.
- A LoggerClient interface with a stub that FAILS CLOSED (every action returns 503 until a real logger is wired in T04).
- Dockerfile per the hardening baseline; pinned requirements.
Write tests (pytest): unit tests plus tests that run against the real compose stack.
Acceptance (show output): 401 on missing/garbage token; 403 on cross-role calls; 422 on unknown fields, id_slot, cache_prompt, oversized max_tokens; probe returns only {"text"}; no timing/usage keys anywhere in responses; with the logger stub, probes return 503; tokens never appear in logs.
Report with security notes for the auditor.
```
Commit: `feat(gateway): authenticated, whitelisted gateway core with fail-closed audit stub` · Tag: `t03-done`
Then run **S-02** (fresh session).

---

## P-04: Logger + verifier (T04)  [HEAVY]

```
CONTEXT: Read AGENTS.md, docs/architecture.md (§8, §4, §2) and docs/task.md (T04).
Implement the logger and the verifier exactly per §8.
Logger: canonical JSON (sorted keys, separators (",",":"), UTF-8, ensure_ascii=False), hash chain with 64-zero genesis, contiguous seq, checkpoints every 10 entries and on demand (Ed25519 signature over ASCII "{seq}:{hash}", key from /run/secrets/log_signing_key), fsync per append, single-writer asyncio lock, POST /append (logger_token), GET /head, GET /entries?after=&limit=. It refuses to append if the on-disk chain is inconsistent.
Verifier: SEPARATE code (do not import logger code), read-only log mount, trusted public key from verifier/trusted_pubkey.pem mounted read-only. GET /verify returns {ok, entries, checkpoints, head, errors[]}. GET /verify/tamper-demo works on an in-memory copy only and tries: modify an entry, delete an entry, reorder two entries, forge a checkpoint, truncate before the last checkpoint, truncate after the last checkpoint. It must report detected true/false honestly; the last case is expected to be NOT detectable and must be labelled as an expected limitation.
Gateway: replace the stub with the real LoggerClient (token, timeouts, fail closed with 503). Log gateway_started, probe_processed (digests only), cache_mode_changed events if those paths exist.
Acceptance (show output): 25 appended entries produce a valid chain and 2 checkpoints, verifier ok:true; each tamper case gives the expected result; stopping the logger makes the gateway return 503; no raw prompt text in any log entry; verifier cannot write the log volume.
Report with security notes.
```
Commit: `feat(audit): hash-chained signed log, independent verifier and tamper demo` · Tag: `t04-done`
Then run **S-03**.

---

## P-05: Run lifecycle, commit-reveal, scoring (T05)  [HEAVY]

```
CONTEXT: Read AGENTS.md, docs/architecture.md (§5, §6, §7, §8) and docs/task.md (T05).
Implement in the gateway: run creation (operator), states created/committing/running/concluded/aborted/failed with a RUN_TIMEOUT_SECONDS auto-abort, one active run at a time, red commit (count, digests, set_digest verified), blue defense upload (schema validation with all limits in §7, stored sealed, bundle_digest returned), per-attack processing (idx uniqueness, SHA-256(prompt) must equal the committed digest else 409, input rules, model call with the correct slot, output rules, heuristic judge, sealed storage), done/conclusion (count check, results JSON, results_digest, aggregate counts), red and blue reports with the asymmetry in §5, all log events in §6 with DIGESTS ONLY mid-run.
Regex rules use the `regex` module with a per-match timeout; a timeout counts as no match. Bundles are data: never evaluated.
The red agent and blue agent come in the next task; here, write test clients that call the endpoints directly.
Acceptance (show output): a full run via test clients reaches concluded; blue report before conclusion is 403; modified prompt after commit is 409; a catastrophic-backtracking regex does not stall the gateway (measure); logged results_digest equals the recomputed digest of the revealed results; verifier returns ok after the run; mid-run log entries contain no outcomes and no raw text.
Report with security notes.
```
Commit: `feat(gateway): commit-reveal evaluation runs with sealed results and scoring` · Tag: `t05-done`
Then run **S-04**.

---

## P-06: Datasets, red agent, blue agent, bundles (T06)

```
CONTEXT: Read AGENTS.md, docs/architecture.md (§6, §7, §2, §4) and docs/task.md (T06).
1. scripts/prepare_datasets.py: reads the raw files the human placed in data/raw/ (AdvBench harmful_behaviors.csv, the Lakera Gandalf ignore-instructions dataset export) and builds data/red/pool.jsonl (records {id, source, category, prompt}, a few hundred, deduplicated) plus a small set of generic wrapper templates (role-play framing, "ignore previous instructions" framing). Fail with a clear message if a raw file is missing. Nothing is downloaded by the script.
2. data/blue/bundles/baseline.json (a few weak rules) and hardened.json (broader rules including injection phrasing and common wrapper patterns) matching the schema in §7. Commit these two files (they are the only data files tracked by git).
3. Red agent: long-running, polls GET /v1/red/work, samples attack_count prompts with the given seed from /data/pool.jsonl (read-only mount), commits digests, waits for running, sends attacks sequentially, calls done. Only talks to the gateway.
4. Blue agent: polls GET /v1/blue/work, loads the named bundle from /data/bundles (read-only mount), uploads it. Only talks to the gateway.
5. Dockerfiles per the hardening baseline, add both services to compose, healthchecks, restart on failure.
Acceptance (show output): creating a run via the operator API makes red and blue act with no human action and the run reaches concluded; baseline vs hardened give different ASR on the same seed; red cannot see blue data and blue cannot see red data (show the exec checks); agents survive a gateway restart.
```
Commit: `feat: add red and blue agents, attack pool builder and defense bundles` · Tag: `t06-done`

---

## P-07: Public API completion (T07)

```
CONTEXT: Read AGENTS.md, docs/architecture.md (§5, §8, §11) and docs/task.md (T07).
Complete every public viewer and operator endpoint in §5: run list and view (commitment digests, timeline, no sealed data), results after conclusion (summary + per-attack idx, prompt_digest, 80-char prompt_preview, outcome, latency_ms; NO full responses, NO rule ids), operator-only item detail, log proxy from the logger, verify and tamper-demo proxies, health aggregation, topology, break-it and timing report endpoints (operator token, stored and logged as breakit_reported / timing_reported), cache-mode GET (public) and POST (operator, logged), OpenAPI at /api/openapi.json, rate limits on heavy endpoints, no CORS (same origin via web).
Also create data/README.md explaining how data is produced.
Acceptance (show output): every endpoint exists and appears in OpenAPI; mid-run and post-run checks prove public endpoints never reveal sealed data; mutations without admin token return 403; public rate limit returns 429; `curl` through the web proxy works for /api/* and returns 404 for /v1/*.
```
Commit: `feat(api): public viewer and operator endpoints with sealed-data protection` · Tag: `t07-done`

---

## P-08: Cache modes and timing experiment (T08)  [HEAVY]

```
CONTEXT: Read AGENTS.md, docs/architecture.md (§9, §12) and docs/task.md (T08). Use docs/verified-notes.md; re-verify anything you are unsure about against the running server.
1. Make sure shared and isolated modes behave exactly as in §9 using the verified field names (isolated: red slot 0, blue slot 1; shared: no pinning; slot erase on conclusion if supported).
2. Write experiments/timing/run.py following the protocol in §9 exactly: warm-up, seeded random ~900-word prefixes distinct per trial, victim via /v1/blue/probe, attacker via /v1/red/probe with max_tokens=1 and temperature 0, HIT vs MISS shuffled with a fixed seed, 40 trials per condition per mode, client-side perf_counter timing, Mann-Whitney U p-value, AUC, median difference, the pre-registered verdict rule (leak detected only if p < 0.01 and AUC > 0.8). Switch modes through the operator endpoint. Post the report (raw samples, stats, environment info including llama.cpp version and model file, verdicts) to /api/experiments/timing/report.
3. Add `make timing`.
Rules: report results AS MEASURED. If shared shows no signal, investigate once (prefix length, slot count, warm-up, max_tokens) and document what you tried; do NOT change the verdict rule after seeing data. If isolated still shows a leak, say so and say why you think so.
Acceptance (show output): the report exists for both modes with raw samples; the verdict is computed by the pre-registered rule; limitations from §9 are written into the report text.
```
Commit: `feat: per-tenant cache isolation and timing side-channel experiment` · Tag: `t08-done`
Then run **S-05**.

---

## P-09: Break-it runner (T09)  [HEAVY]

```
CONTEXT: Read AGENTS.md, docs/architecture.md (§10, §2, §3, §4) and docs/task.md (T09).
Implement the break-it runner: breakit/harness.py (host side: docker inspect for config audit and to collect target IPs, `docker compose exec -T red|blue` for in-container probes, direct HTTP for operator and public probes), breakit/container_probes.py (copied into the red and blue images), the full probe table in §10 (IDs N1..N4, F1..F3, P1..P5, A1..A8, L1..L3, C1..C6), the report schema, a readable table in the terminal, posting to /api/breakit/report. Add `make breakit`.
Probes must be REAL attempts (real connects, real writes, real syscalls), except category C which audits configuration. L2 passes only when the verifier honestly reports tail truncation as not detectable.
Also write scripts/breakit-negative-demo.sh: in a scratch copy of the compose file, weaken one control (for example attach red to blue-net, or remove cap_drop from red), bring it up, run the harness and show that the matching probes FAIL, then tear the scratch stack down.
Acceptance (show output): all probes pass on the real hardened stack; the negative demo shows failing probes; the report is visible at /api/breakit/latest.
```
Commit: `feat: break-it runner with real isolation probes and negative demo` · Tag: `t09-done`

---

## P-10: Frontend (T11)  [needs docs/design.md]

```
CONTEXT: Read AGENTS.md, docs/architecture.md (§5, §11), docs/prd.md, docs/design.md and docs/task.md (T11). The API contract is /api/openapi.json from the running gateway.
Build the frontend with Vite + React + TypeScript, built in a multi-stage Dockerfile into the `web` image (Caddy). Implement every view in §11 against the REAL API: Overview, Runs (create run for the operator, timeline, live progress by polling every 2-3 s, results), Audit log (table, verify now, tamper demo panel including the honest not-detectable row, head hash copy), Break-it report, Timing experiment (HIT vs MISS distribution plots per mode, medians, p-value, AUC, verdict, cache-mode toggle for the operator), Threat model (render docs/threat-model.md at build time), Operator login (admin token kept in memory only).
Requirements: loading, empty and error states everywhere; no mock data in the production build; responsive layout; no console errors; a visitor without a token sees read-only data and nothing sealed; follow docs/design.md for look and feel, and ask before deviating from the API contract.
Acceptance (show output): `npm run build` succeeds; web container serves the app; every view shows real data from a completed run; operator actions work with the token and are blocked without it; Lighthouse or equivalent sanity check not required, but the app must work on a phone-width viewport.
```
Commit: `feat(web): functional dashboard for runs, audit log, break-it and timing results` · Tag: `t11-done`

If `docs/design.md` is not ready by the end of Day 2, use this fallback line instead of the design reference: "Use a clean minimal design (system fonts, neutral palette, one accent color); follow docs/prd.md §6 for layout."

---

## P-11: Production deployment (T12)

```
CONTEXT: Read AGENTS.md, docs/architecture.md (§2, §3, §4, §14) and docs/deployment-guide.md and docs/task.md (T12).
Create docker-compose.prod.yml (override only what differs): Caddy with automatic HTTPS for ${DOMAIN}, restart: unless-stopped on all services, only ports 80 and 443 published by web (no other service publishes ports), documented NET_BIND_SERVICE exception if needed, writable named volumes only for Caddy data/config. Create scripts/seed-real-run.sh (creates one baseline run and one hardened run through the operator API and waits for conclusion), scripts/backup.sh (archives log-data and gateway-data with checksums), and a `make prod-up` target.
Do NOT run anything against a remote server yourself unless the human gives you shell access in this session; otherwise output the exact commands for the human to run and verify them locally with the prod override against localhost.
Acceptance (show output): prod compose validates (`docker compose -f docker-compose.yml -f docker-compose.prod.yml config`), starts locally, shows only 80/443 mapped, `/v1/*` is 404 via web, seed script completes a real run, backup script produces archives.
```
Commit: `chore(deploy): production compose override, seeding and backup scripts` · Tag: `t12-done`

---

## P-12: Documentation and evidence (T13)

```
CONTEXT: Read AGENTS.md, docs/architecture.md (§12) and docs/task.md (T13). Read the code only as needed to be accurate.
Write: README.md (what it is, architecture summary with the network diagram in text, one-command start, one-command test, how to read results, screenshot placeholders), docs/threat-model.md (two pages maximum, plain language, based on §12 and on what was actually built and tested; state every limitation; no claims that are not backed by a test or measurement), finalise docs/verified-notes.md, docs/demo-script.md (under five minutes: exact commands, what the audience sees, what to say in one sentence per step, a fallback for each step that may fail live).
Rules: no marketing claims, no market-size numbers, no "fully secure" wording. Reference actual test names and report fields. Leave clearly marked placeholders for screenshots and real measured numbers the human will fill in.
```
Commit: `docs: README, threat model, verified notes and demo script` · Tag: `t13-done`

---

## P-13: Final clean-slate verification (T14)

```
CONTEXT: Read AGENTS.md and docs/task.md (T14).
Do not add features. On a fresh clone in a temp directory: run gen-secrets, build, up, wait for healthy, run `make check`, create one run through the operator API, verify the log, run the tamper demo. Report every failure with root cause. Fix only bugs (smallest possible change), re-run until clean. Then update docs if any command changed.
End with a table: command | result | evidence.
```
Commit: `fix: final verification fixes` (only if needed) · Tag: `v1.0`

---

# Security audit prompts (S): each in a FRESH conversation, written from the spec only

Rule for all S prompts: **do not open or read the implementation** of the component under test. Work only from `docs/architecture.md`. You are an adversary. Write tests that try to break the property. Report each test as PASS (property held) or FAIL (property broken), with the exact request or command used.

## S-01: Compose and container hardening review (after P-01)

```
You are an independent security reviewer. Read only AGENTS.md (§3) and docs/architecture.md (§2, §3, §4). Do NOT read other repository code.
Review docker-compose.yml and the Dockerfiles as configuration artifacts against every point in §2 to §4 and the invariants SI-01..SI-04, SI-10, SI-11.
Produce a checklist table: requirement | where in the file | PASS/FAIL | evidence. Then actively test on the running stack: attempt name resolution and TCP connects from red to blue/model/logger, check /proc/self/status for CapEff, NoNewPrivs, Seccomp, check write access to /, check /run/secrets contents, check mounted paths.
Do not modify any file. List fixes needed as a numbered list.
```
Commit: none (fixes by the Build Lead in a normal P-session, then `fix: address S-01 findings`).

## S-02: Gateway authorization tests (after P-03)

```
You are an adversary. Read only docs/architecture.md (§5, §3) and AGENTS.md (§3). Do NOT read gateway source.
Write tests/security/test_gateway_authz.py that run against the real running stack and try to violate: authentication (no token, garbage token, empty token, token of the other role, admin token header from a tenant), authorization (every tenant endpoint with the wrong role, every operator endpoint with tenant tokens), input whitelisting (unknown fields, id_slot, cache_prompt, negative and huge max_tokens, oversized prompts, wrong types, nested junk), response hygiene (no timings, usage, slot or cache keys in any tenant response), rate limiting, and the public proxy (/v1/* must be 404 through web).
For each test assert the defense held. Run them and report PASS/FAIL for each. Do not change gateway code; list failures.
```
Commit: `test(security): independent gateway authorization tests` 

## S-03: Audit log and verifier attacks (after P-04)

```
You are an adversary. Read only docs/architecture.md (§8) and AGENTS.md. Do NOT read logger or verifier source.
Write tests/security/test_audit_log.py: produce entries through the gateway, then on a COPY of the log files attempt: edit a field, change a hash consistently without re-chaining, delete an entry, duplicate an entry, reorder entries, replace a checkpoint signature, replace a checkpoint with one signed by a different key, truncate before and after the last checkpoint, insert a forged entry with a recomputed valid hash chain after the tamper point. Feed each copy to an independent re-implementation of verification written by you from §8 AND to the real verifier endpoint if it accepts a path, otherwise through a temporary read-only mount.
Also test: stopping the logger makes the gateway fail closed (503); no raw prompt or response text appears in any entry; the verifier cannot write to the log volume.
Report PASS/FAIL per attack and state clearly which attacks are expected to be undetectable (tail truncation).
```
Commit: `test(security): independent audit log tamper tests`

## S-04: Commit-reveal attacks (after P-05)

```
You are an adversary. Read only docs/architecture.md (§5, §6, §7) and AGENTS.md. Do NOT read gateway source.
Write tests/security/test_commit_reveal.py against the running stack: swap an attack prompt after commit, resend or skip idx values, send attacks before running state, call done early or late, read blue's report and red's report before conclusion, read the public run view and results before and after conclusion (must never expose prompts beyond the 80-char preview after conclusion, never any before, never rule ids, never full responses), submit oversized and malformed bundles, submit a regex bundle designed for catastrophic backtracking and measure gateway latency for other requests during that time, start a second run while one is active, abort and timeout behavior, confirm results_digest in the log equals the recomputed digest of the revealed results.
Report PASS/FAIL per test and any leak you found.
```
Commit: `test(security): independent commit-reveal and sealed-data tests`

## S-05: Timing experiment methodology review (after P-08)

```
You are a skeptical statistician and security reviewer. Read docs/architecture.md (§9) and then read experiments/timing/run.py and its stored report.
Check: is the protocol exactly the one in §9; is HIT/MISS order really shuffled with a fixed seed; are prefixes distinct per trial; is warm-up discarded; are the statistics computed correctly (verify Mann-Whitney U and AUC by recomputing from the raw samples with a separate script); is the verdict rule applied exactly as pre-registered; does the report contain limitations; are there signs of tuning or cherry-picking (compare git history of the rule); is the measured effect plausible given prefill cost.
Output: findings list with severity, and a one-paragraph plain-language summary of what the data does and does not show.
```
Commit: none (fixes via a normal P-session).

## S-06: Final adversarial review (before freeze)

```
You are an adversary with 60 minutes. Read only docs/architecture.md (§1, §10, §12) and AGENTS.md. Do not read source code until you have attempted attacks from the outside.
Goal: break any of these claims with real attempts against the running stack: red cannot learn blue's defense logic; blue cannot see red's attack prompts before conclusion; tenants cannot reach the model or each other; tenants cannot reach the internet; logged history cannot be changed undetected (apart from tail truncation); public visitors cannot read sealed data or call tenant or operator endpoints; secrets are not exposed anywhere (env, logs, images, API errors).
After attempts, read the compose file and Dockerfiles for anything you missed. Output: list of successful attacks (with exact steps), list of failed attempts, and a short list of residual risks that should appear in docs/threat-model.md.
```
Commit: none.

---

# Extra and stretch prompts (X)

## X-01: Custom seccomp profile (T10, stretch, only after T09 is green)

```
CONTEXT: Read AGENTS.md and docs/architecture.md (§3, §15 item 5).
Create security/seccomp-tenant.json derived from Docker's default profile for the version installed (do not write one from memory) with additional denies for ptrace, keyctl, personality changes, userfaultfd and similar if they are not already denied. Apply it only to red, blue (and optionally gateway) through security_opt, verifying how Compose resolves the path in the installed version. Run the full `make check`. If ANY service or probe breaks, revert to Docker's default profile and report why.
```
Commit: `feat(security): stricter seccomp profile for tenant containers`

## X-02: Per-tenant model instances fallback (only if slot pinning is unreliable)

```
CONTEXT: Read AGENTS.md and docs/architecture.md (§9 fallback).
Replace the single model service with model-red and model-blue instances on separate internal networks reachable only by the gateway, route by tenant, keep the same cache modes semantics (shared mode becomes: both tenants routed to the same instance). Update the compose file, the gateway routing, the break-it config probes (C3), the timing experiment and the docs. Report memory use for both instances. Do not weaken any invariant.
```
Commit: `refactor: per-tenant model instances for cache isolation`

---

# Hotfix and help prompts (H)

## H-01: A container will not start

```
A service fails to start. Do not change security settings to make it start. Show me: `docker compose ps`, `docker compose logs --tail=100 <service>`, and `docker inspect <container>` fields relevant to the failure. State the root cause in one sentence, propose the smallest fix that keeps SI-01..SI-12 intact, apply it, and prove it with the healthcheck output. If the only fix weakens an invariant, stop and ask me.
```

## H-02: Tests pass but I suspect they are fake

```
Audit the tests for <component>. For each security test, identify what exact attack it performs and which assertion would fail if the defense were removed. Then PROVE it: temporarily disable the defense in a scratch copy, run the test, show that it fails, and restore. List any test that still passes with the defense disabled; those tests are worthless and must be rewritten.
```

## H-03: The agent drifted off scope

```
Stop. Re-read AGENTS.md and docs/task.md for task <id>. List every change you made that is not required by that task's acceptance criteria. Revert them (git) unless I approve each one. Then continue with the task only.
```

## H-04: Regression after a change

```
Something that worked now fails: <describe>. Use git to find the commit that introduced it (bisect if needed), explain the cause, fix it with the smallest change, add a test that would have caught it, and run `make check`. Do not touch unrelated files.
```

## H-05: Model is slow or requests time out

```
Measure before changing anything: tokens per second from scripts/model-smoke.sh, CPU and memory of the model container (`docker stats`), the configured threads, ctx, parallel and max_tokens. Report the numbers, then propose changes in this order: lower ATTACK_MAX_TOKENS, set MODEL_THREADS to the number of physical cores available to the VM, reduce MODEL_CTX, switch to a smaller quantization. Apply one change at a time and re-measure. Do not remove any security limit.
```
