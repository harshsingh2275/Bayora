# Bayora: Task Plan (4 days, sequential)

Work the tasks **in order**. Each task has acceptance criteria; a task is done only when all of them are shown with real output. Time budgets are planning targets, not measurements.

Legend: **MUST** = required for submission. **SHOULD** = important, drop only after the cut list says so. **STRETCH** = only if time is left.
Prompt IDs refer to `docs/prompt.md`. Architecture sections refer to `docs/architecture.md`.

---

## Schedule at a glance

| Day | Goal | Tasks |
|---|---|---|
| Day 1 | Foundation running and hardened | T00, T01, T02, T03 |
| Day 2 | Audit log, run lifecycle, agents | T04, T05, T06 |
| Day 3 | Public API, timing leak, break-it | T07, T08, T09 (+ T11 frontend in a second session once `docs/design.md` exists) |
| Day 4 | Frontend finish, deploy, docs, freeze | T11, T12, T13, T14 |

Checkpoints (human): end of Day 1 compose hardening audited (S-01, S-02). End of Day 2 log and commit-reveal audited (S-03, S-04). End of Day 3 break-it report green and timing numbers sane (S-05). Day 4 final audit (S-06) and a clean-VM run from scratch.

---

## T00: Repository bootstrap  [MUST, Day 1, ~1h]  (prompt P-01, clubbed with T01)

**Do:** create the repo layout from architecture §13, `.gitignore`, `.env.example`, `Makefile` with the targets listed in §13 (targets for components that do not exist yet may print "not implemented yet" but must exist), `scripts/gen-secrets.sh` and `scripts/sync-agents.sh`, copy `docs/agents.md` to `AGENTS.md`.

`gen-secrets.sh` must: create `secrets/` (mode 0700); generate random 32-byte hex tokens for red, blue and admin plus `logger_token`; write their SHA-256 files; generate an Ed25519 keypair with OpenSSL (private to `secrets/log_signing_key`, public to `verifier/trusted_pubkey.pem`); set file modes 0644 inside the 0700 directory; refuse to overwrite existing secrets unless `--force`; print only where files were written, never the secret values.

**Done when:** `make` targets exist; `gen-secrets.sh` run twice does not overwrite; `git status` shows no secret files tracked; `.gitignore` covers `secrets/`, `.env`, `data/` (except bundles) and model files.

## T01: Compose skeleton and hardening  [MUST, Day 1, ~2h]  (prompt P-01)

**Do:** `docker-compose.yml` with all seven services and five networks per architecture §2, hardening per §3, secrets and volumes per §4. Services may be tiny stubs (health endpoint only) for now. `web` serves a placeholder page and proxies `/api/*` to the gateway; `/v1/*` returns 404. Every service has a healthcheck.

**Done when:** `docker compose up -d` brings everything healthy; `docker compose config` shows internal networks, non-root users, cap_drop ALL, limits; manual proof that `docker compose exec red` cannot resolve `blue`, `model`, `logger`; `curl localhost:8088/v1/red/work` returns 404.
**Audit:** S-01 (config review session).

## T02: Model service  [MUST, Day 1, ~1h]  (prompt P-02)

**Do:** add the `model` service (llama.cpp server, pinned tag, §15 items 1 to 4 verified and recorded in `docs/verified-notes.md`), mount `data/models` read-only, `--parallel 2`, CPU only, limits. A script `scripts/model-smoke.sh` sends one chat request from a throwaway container attached to `model-net` and prints the reply and latency.

**Done when:** model reports healthy; smoke script returns a sensible completion; `docs/verified-notes.md` lists the exact image tag, flags, the slot pinning field name, the cache field name, and the slot erase endpoint if it exists, each with how it was verified.

## T03: Gateway core  [MUST, HEAVY, Day 1, ~3h]  (prompt P-03)

**Do:** FastAPI gateway per architecture §5 (tenant parts only for now): token auth, role checks, pydantic whitelist models with `extra="forbid"`, rate limiting, SQLite schema (runs, commitments, bundles, attacks, settings), model client that builds the request itself (fixed system prompt, temperature 0, `max_tokens` cap) and strips non-whitelisted response fields, cache-mode setting (`isolated` or `shared`) used when building slot parameters (§9), `/v1/red/probe` and `/v1/blue/probe`, and a **logger client interface** with a stub implementation that fails closed when the real logger is not configured.

**Done when:** unit tests plus real-container tests show: 401 with no or bad token; 403 on cross-role calls; 422 on unknown fields, `id_slot`, `cache_prompt`, oversized `max_tokens`; probe returns only `{"text"}`; no timing or usage fields leak; with the logger stub failing, probes return 503.
**Audit:** S-02 (separate session writes authorization tests from the spec only).

## T04: Audit logger and verifier  [MUST, HEAVY, Day 2, ~3h]  (prompt P-04)

**Do:** `logger` service and `verifier` service per architecture §8: canonical JSON, hash chain, checkpoints every 10 entries and on demand, Ed25519 signatures with the key from `secrets/log_signing_key`, fsync, single-writer lock, `POST /append`, `GET /head`, `GET /entries`. Verifier is independent code (does not import logger code), mounts the log read-only, pins the trusted public key, implements `GET /verify` and `GET /verify/tamper-demo` with all six tamper cases including the honest "truncate after last checkpoint: not detectable" row. Replace the gateway's logger stub with the real client (fail closed).

**Done when:** appending 25 entries yields correct chain and 2 checkpoints; verifier returns `ok: true`; each tamper case returns the expected detected/not-detected result; killing the logger makes the gateway return 503; no raw prompt text appears in any log entry.
**Audit:** S-03.

## T05: Run lifecycle (commit-reveal) and scoring  [MUST, HEAVY, Day 2, ~3h]  (prompt P-05)

**Do:** implement architecture §6 and §7 in the gateway: run creation (operator), states and transitions, commit endpoints, digest verification per attack, defense bundle validation and sealed storage, input and output rule application with `regex` timeouts, heuristic judge, sealed per-attack storage, conclusion with `results_digest`, red and blue reports with the asymmetry in §5, the run timeout and abort, all log events per §6 (digests only mid-run).

**Done when:** an end-to-end run using simple test clients reaches `concluded`; blue report before conclusion returns 403; a changed prompt after commit returns 409; a hostile regex does not stall the gateway; the logged `results_digest` equals the recomputed digest of the revealed results; the audit log verifies `ok`.
**Audit:** S-04.

## T06: Datasets, red agent, blue agent, bundles  [MUST, Day 2, ~2.5h]  (prompt P-06)

**Do:** `scripts/prepare_datasets.py` builds `data/red/pool.jsonl` from the sources in §7 (the human downloads the raw files first; see manual actions); `data/blue/bundles/baseline.json` and `hardened.json`; the red agent and the blue agent (long-running, poll `work`, act per §6, only ever talk to the gateway, read their data mounts read-only). Rebuild compose so both run.

**Done when:** creating a run from the operator API causes red and blue to commit and the run to finish with no human action; `baseline` and `hardened` produce different ASR on the same seed; red container has no access to blue data and vice versa (verified by the S-01 style checks).

## T07: Public API completion and operator controls  [MUST, Day 3, ~2h]  (prompt P-07)

**Do:** all public viewer and operator endpoints from §5, log proxying, verifier proxying, topology, health aggregation, report storage endpoints for break-it and timing, CORS off (same-origin through `web`), operator token handling, rate limits on heavy endpoints, OpenAPI document. Seed `data/README.md` explaining how to produce data.

**Done when:** every endpoint in §5 exists and is documented in OpenAPI; public endpoints never reveal sealed data (checked mid-run and after); mutations without the admin token return 403; public rate limit returns 429 when exceeded.

## T08: Cache modes and timing experiment  [MUST, HEAVY, Day 3, ~4h]  (prompt P-08)

**Do:** implement the two modes exactly per §9 against the verified llama.cpp behavior, the slot erase at conclusion if supported, and `experiments/timing/run.py` with the protocol, statistics and pre-registered verdict rule. Post the report to the gateway.

**Done when:** the experiment runs for both modes and produces a report with raw samples. Results are reported **as measured**. If `shared` shows no signal, investigate once (prefix length, slot count, `max_tokens=1`, warm-up) and record the outcome; do not tune the rule. If the signal exists only in `shared`, the isolated result is the headline.
**Audit:** S-05 (statistics and methodology review).
**Fallback:** per-tenant model instances (architecture §9) if slot pinning is unreliable.

## T09: Break-it runner  [MUST, HEAVY, Day 3, ~3h]  (prompt P-09)

**Do:** `breakit/` harness and in-container probes implementing the full table in §10, report schema, table output, posting to the gateway. Add `make breakit`. Probes must be real attempts, not config reads, except category C (config audit).

**Done when:** `make breakit` prints a table with every probe; all pass on the hardened stack; deliberately weakening one control (for example adding a second network to red in a scratch copy of the compose file) makes the matching probe **fail**. Keep that demonstration as `scripts/breakit-negative-demo.sh`.

## T10: Custom seccomp profile  [STRETCH, ~1.5h]  (prompt X-01)

Only after T09 is green. Must not break any service; fall back to Docker's default profile if it does.

## T11: Frontend  [MUST, Day 3 start to Day 4, ~5h]  (prompt P-10)

Blocked until `docs/design.md` exists. If it does not exist by the end of Day 2, build the minimal fallback UI described in `docs/prd.md` §6 and restyle later.
**Do:** implement the views in architecture §11 against the real API, built into the `web` image, polling live data, operator login held in memory, error and loading states, responsive layout.
**Done when:** every view works against the running stack with real data; a visitor without a token sees read-only data and no sealed content; production build is served by `web`; no console errors.

## T12: Production deployment  [MUST, Day 4, ~3h]  (prompt P-11)

Follow `docs/deployment-guide.md`. Production compose override, Caddy with automatic HTTPS, restart policies, only ports 80 and 443 published, secrets generated on the server, model downloaded on the server, seed real runs (`scripts/seed-real-run.sh`: one `baseline` and one `hardened` run, then break-it and timing against the deployed stack).
**Done when:** the public URL loads over HTTPS, shows real runs, a verified log, the break-it report and the timing report; `https://<domain>/v1/red/work` returns 404; only 80, 443 (and restricted SSH) are reachable from outside.

## T13: Documentation and evidence  [MUST, Day 4, ~2.5h]  (prompt P-12)

`README.md` (what it is, architecture, one-command start, one-command test, screenshots placeholders), `docs/threat-model.md` (from §12, two pages maximum, plain language, no overclaiming), `docs/verified-notes.md` finalised, `docs/demo-script.md` (under five minutes, exact commands and what the audience sees). The human fills in screenshots and real numbers.

## T14: Final audit and freeze  [MUST, Day 4, ~2h]  (prompts S-06, P-13)

Clean-slate run on a fresh clone: `gen-secrets`, build, up, `make check`, one run, verify log. Fix only bugs. Tag `v1.0`. No new features after this point.

---

## Cut list (apply in this order if behind schedule; never cut a MUST)

1. T10 custom seccomp (STRETCH)
2. Extra frontend polish beyond the required views
3. Per-attack table pagination and filters
4. `shared`-mode experiment sample size from 40 to 25 trials per condition (state it in the report)
5. Break-it categories P5 and N4 (keep N1 to N3, F, A, L, C)
6. Seeding the deployed site with more than one run per bundle

**Never cut:** isolation (T01 to T03), audit log and verifier (T04), commit-reveal (T05), the break-it runner (T09), the threat model (T13), and honest reporting of timing results.

## Definition of done for the whole project

On a clean Linux host: one command starts the stack, one command (`make check`) runs lint, tests, security tests and the break-it table with every probe passing; a run can be created from the site and completes on its own; the verifier reports `ok`; the tamper demo shows detection (and the honest limitation); the timing report shows both modes with real data; the threat model lists what is not protected; the public site works over HTTPS for a visitor with no token.
