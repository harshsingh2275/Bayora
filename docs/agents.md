# AGENTS.md: Rules for the Coding Agent (Bayora)

Copy this file to the repository root as `AGENTS.md` (`make sync-agents`). If your tool does not read it automatically, the human will paste it at the start of every session. Read it fully before doing anything.

## 1. What you are building

**Bayora** is a working platform for secure adversarial AI safety testing. A red team (attacker), a blue team (defender) and a client LLM (model under test) run at the same time in one shared Docker environment. Isolation between them is enforced and tested, every action is recorded in a hash-chained, signed audit log, and a break-it runner plus an independent verifier prove the claims.

This is a **personal hackathon project** (Hack in Hills '26) built in **4 days** by a team of 3. Scope is deliberately limited, but what exists must actually work. It is a real, deployed, functional system, not a mock-up and not a prototype with fake data. Never fabricate results, screenshots or test output.

The human does not write code. You write all code, configs, tests and scripts. The human audits, so every security-relevant choice must be readable and commented.

## 2. Source-of-truth order

1. `docs/architecture.md` (design; section numbers like §5 are referenced everywhere)
2. `docs/task.md` (what to do, in order, with acceptance criteria)
3. `docs/prompt.md` (the exact prompt for the current task)
4. `docs/prd.md` (what the product must do and why)
5. `docs/design.md` (frontend only, when it exists)

If two documents conflict, or a document conflicts with reality, **stop and ask**. Do not silently pick one.

## 3. Non-negotiable security invariants

Breaking any of these is a failure even if every test passes.

- **SI-01** No container is privileged. No `network_mode: host`, no `pid: host`, no `devices`, no `/var/run/docker.sock` mount, ever.
- **SI-02** Every custom container: non-root user, `cap_drop: [ALL]`, `no-new-privileges`, `read_only: true` with `tmpfs /tmp`, and memory, CPU and pids limits. Documented exceptions only (architecture §3), each commented in the compose file.
- **SI-03** `red-net`, `blue-net`, `model-net`, `log-net` are `internal: true`. Only the gateway is attached to more than one of them. Only `web` and `gateway` are on `front-net`. Tenants never get internet access.
- **SI-04** The gateway is the only route to the model. Only the gateway talks to the logger. Tenants never do.
- **SI-05** Tenant and admin tokens are stored as hashes in the gateway, compared with `hmac.compare_digest`, and never logged or returned.
- **SI-06** Every request model uses `extra="forbid"`. Never forward client-supplied model parameters (`id_slot`, `cache_prompt`, etc.). The gateway builds the model request itself.
- **SI-07** Fail closed. If the audit logger is unreachable, the gateway rejects the action with 503.
- **SI-08** No raw prompts, responses or bundles in the audit log or in public API responses before a run concludes. Strip `timings`, `usage`, cache and slot fields from model responses.
- **SI-09** Defense bundles are data. Never `eval`, `exec`, import or shell out on tenant-supplied content. Regex matching must use a timeout.
- **SI-10** Secrets never enter git, logs, images or error messages. `.env`, `secrets/` and `data/` (except `data/blue/bundles/*.json`) are gitignored.
- **SI-11** The public proxy exposes `/api/*` only. `/v1/*` must return 404 through `web`. Public endpoints are read-only; mutations need the operator token.
- **SI-12** **Never weaken a control to make a test or feature pass.** If a control blocks something you need, stop and ask.

## 4. Engineering rules

- Python 3.12, FastAPI, pydantic v2, httpx, aiosqlite, `cryptography`, `regex`, pytest. `scipy` only inside `experiments/`. Frontend: Vite + React + TypeScript. Do not add other dependencies without asking.
- **Pin exact dependency versions** (requirements files and lockfiles). Avoid versions released in the last two weeks.
- Keep files small and readable (aim under 300 lines). Comment every security-relevant line with `# SECURITY:` and one plain sentence on what boundary it enforces.
- Type hints everywhere. Structured JSON logs to stdout, never containing secrets or prompt text.
- Configuration through environment variables and file secrets only. No hard-coded tokens.
- No hidden global state. No background threads that can outlive a request without a clear shutdown path.
- Do not add features, endpoints, dashboards or dependencies that are not in the task. The cut list in `docs/task.md` tells you what may be dropped if time runs short.

## 5. Verification rules (the most important section)

- Never say a task is done without running the checks and showing their real output.
- **Security tests must try to violate the property and assert that the attempt fails.** A test that only checks the happy path does not count.
- Isolation tests run against the **real containers**, not mocks. Do not mock the thing being tested.
- You must not write the tests for a component you just implemented *and* grade them yourself when the prompt says a separate audit session is required (S-prompts). Those are written from the spec only.
- **Verify third-party behavior; do not rely on memory.** For llama.cpp flags and request fields, Docker Compose options and library APIs, check `--help`, installed package docs or official docs for the version you pinned, and record what you found (architecture §15 lists what must be verified).
- If something cannot be verified in this environment, say so explicitly in your report. Never claim it works.
- Run `make check` before reporting done once it exists (created in T00).

## 6. Commits and reports

- Conventional Commits (`feat:`, `fix:`, `test:`, `chore:`, `docs:`). One commit per task at minimum, small logical commits inside a task are welcome.
- After each task finishes and `make check` passes: commit, then tag `tNN-done` (for example `t03-done`). Never force-push. Never commit `data/models`, secrets or datasets.
- End every task with this report:

```
TASK: <id and name>
CHANGED: <files and a one-line reason each>
HOW TO VERIFY: <exact commands the human can run>
EVIDENCE: <real output of those commands, trimmed>
SECURITY NOTES: <boundaries enforced, decisions the auditor must review, exceptions>
NOT VERIFIED / RISKS: <anything unproven, assumptions, flags that may differ by version>
```

## 6b. Stop and ask when

- a dependency outside the approved list seems necessary
- a network, capability, mount, user or seccomp setting would need to change
- the spec is ambiguous in a way that affects security
- a test can only pass by weakening a control
- the task is taking more than 50% over its time budget in `docs/task.md`
- a third-party behavior differs from what the docs assume

## 7. Forbidden

- Faking, hard-coding or pre-filling results, timings, test outcomes or log entries
- Editing the audit log by hand or adding any API that rewrites history
- Disabling healthchecks, limits or hardening to get something to start
- Using `latest` image tags in committed files
- Printing, logging or committing secrets
- Making outbound internet calls from containers at runtime (downloads happen in documented setup steps on the host)

## 8. Time awareness

Four days total. Prefer the simplest design that satisfies the acceptance criteria. When a decision is between "more complete" and "verified and working", choose verified and working. Use the cut list in `docs/task.md` instead of silently dropping requirements.
