# Bayora: Product Requirements Document

## §1. Summary

**Product:** Bayora, secure infrastructure for adversarial AI safety testing.
**One line:** a shared environment where an AI red team, a blue team and a model under test run at the same time without leaking state to each other, with a tamper-evident record that anyone can re-verify.
**Context:** hackathon project for Hack in Hills '26, problem statement 04 ("Securing Adversarial AI Safety Testing Infrastructure"), built in 4 days by a team of 3 using an AI coding agent. Limited scope, but everything delivered must work for real.

## §2. Problem

AI safety findings are only as trustworthy as the environment that produced them. If red, blue and the model share a sandbox and any one can see or infer another's state:

- blue overfits to attacks it has seen, red tunes to a defense it can infer;
- a contaminated model carries state between tests;
- the outcome is a confident, wrong safety verdict, and a model deployed on its strength.

**Core question:** how can adversaries, defenders and the model run together without leaking state or creating side channels?

## §3. Users

| User | Need | How Bayora serves them |
|---|---|---|
| AI safety team running red/blue evaluations | Results they can defend | Isolated tenants, commit-reveal runs, verifiable log |
| Independent auditor | Reconstruct and check a finding without trusting the platform | Public verifier, signed checkpoints, revealed results with digests |
| Platform operator | Run and monitor evaluations | Operator controls and a live dashboard |
| Hackathon judge / visitor | Understand and see it working in minutes | Public read-only site with real runs, break-it report, timing report |

## §4. Goals and non-goals

**Goals**
- G1. Enforce isolation between red, blue and model, and prove it with tests that attack the isolation.
- G2. Prevent leakage of attack prompts and defense logic before a run concludes (commit-reveal).
- G3. Show and mitigate an LLM-specific leak (shared prefix-cache timing), with honest measurements.
- G4. Keep a tamper-evident, independently verifiable audit trail.
- G5. Be deployable on a plain Linux host with standard tools and no special hardware.
- G6. State residual risk plainly.
- G7. Ship a working public site (HTTPS) with real data.

**Non-goals**
- Training or fine-tuning models, large-scale attack campaigns, a multi-tenant SaaS with accounts and billing, GPU inference, multi-host scaling, a mobile app, defeating kernel-level attacks.

## §5. Functional requirements

Each requirement has an ID used in tests and docs.

**Isolation**
- FR-01 Red, blue and the model run as separate containers on separate internal networks; only the gateway bridges them.
- FR-02 No tenant can reach another tenant, the model, the logger, the verifier or the internet.
- FR-03 Each container is hardened (non-root, no capabilities, no new privileges, read-only root, resource limits) per architecture §3.
- FR-04 Secrets and data are mounted per service; no tenant sees another tenant's data or secrets.

**Gateway and evaluation**
- FR-05 Tenants authenticate with tokens; roles are enforced on every endpoint; requests are whitelisted; model parameters are never client-controlled.
- FR-06 An operator can create an evaluation run (name, number of attacks, seed, defense bundle).
- FR-07 Red commits to digests of its attack set; blue commits to a digest of its defense bundle; both are logged before the run starts.
- FR-08 During a run, nothing about the other side's content is exposed through any API or log.
- FR-09 Each attack is checked against its commitment, passed through blue's input rules, sent to the model, passed through output rules, and scored.
- FR-10 On conclusion, results are revealed (blue gets prompts, outcomes and rule ids; red gets outcomes; the public gets counts and attack metadata: digests, source, category, outcome, latency; no prompt text), and the logged `results_digest` matches the revealed data.
- FR-11 Scoring is a heuristic attack success rate (ASR), always labelled as heuristic.
- FR-12 Red and blue agents run autonomously and only talk to the gateway.

**Audit**
- FR-13 Every significant event is appended to a hash-chained log by a single logger, with signed checkpoints.
- FR-14 The log contains digests and aggregates, never raw prompts or responses.
- FR-15 An independent verifier validates the whole log and a pinned public key.
- FR-16 A tamper demonstration shows what is detected and, honestly, what is not (tail truncation).
- FR-17 If the logger is unavailable the gateway refuses actions (fail closed).

**LLM-specific**
- FR-18 The gateway supports `shared` and `isolated` cache modes.
- FR-19 A timing experiment measures cross-tenant prefix-cache leakage in both modes with a pre-registered verdict rule and reports raw data and statistics.
- FR-20 In `isolated` mode, tenants are pinned to separate model slots and slots are erased at run conclusion where supported.

**Break-it**
- FR-21 A break-it runner performs real attacks on network, filesystem, privilege, authorization and log integrity, plus a configuration audit, and publishes a pass/fail report.
- FR-22 A negative demonstration proves the probes fail when a control is removed.

**Public site**
- FR-23 A public, read-only dashboard shows health, architecture, runs and results, audit log with a verify button and tamper demo, break-it report, timing results and the threat model.
- FR-24 Operator actions (create or abort run, toggle cache mode) require the admin token.
- FR-25 The public proxy exposes `/api/*` only.

**Operations**
- FR-26 One command starts the stack; one command (`make check`) runs lint, tests, security tests and the break-it table.
- FR-27 Production deployment uses HTTPS and publishes only ports 80 and 443.

## §6. Frontend requirements

Detailed visual design lives in `docs/design.md`. Functional requirements for each view are in architecture §11.

**Fallback minimal UI (use only if `docs/design.md` is missing):** a single-page app with a top navigation bar (Overview, Runs, Audit log, Break-it, Timing, Threat model, Operator). System font stack, neutral background, one accent color, cards with 1px borders, tables with sticky headers, status badges (green pass, red fail, amber unknown), monospace for hashes with a copy button, no animations beyond a loading spinner. Mobile: navigation collapses into a menu, tables scroll horizontally inside their card.

Mandatory states for every view: loading, empty, error (with retry), and "operator token required" where relevant.

## §7. Non-functional requirements

- NFR-01 **Security:** all invariants SI-01..SI-12 in `docs/agents.md` hold.
- NFR-02 **Honesty:** no claim in the UI or docs without a test or measurement behind it.
- NFR-03 **Reproducibility:** a fresh clone plus documented manual steps yields a working system; the demo uses the same code as the deployment.
- NFR-04 **Performance:** a run of 50 attacks should finish in minutes on a 2 to 4 vCPU CPU-only host using a ~0.5B-parameter quantized model. This is a planning target to be measured, not a verified figure.
- NFR-05 **Resource limits:** the whole stack fits a VM of 8 GB RAM and 4 vCPU for development; a smaller production VM may be used only after measuring.
- NFR-06 **Maintainability:** small readable files, pinned dependencies, security-relevant lines commented.
- NFR-07 **Privacy:** all data stays local; no external APIs at runtime.

## §8. Acceptance (project level)

The project is accepted when the "Definition of done for the whole project" in `docs/task.md` is satisfied, and each FR above has at least one test, probe or demonstrable check recorded in the final evidence.

## §9. Constraints and assumptions

- 4 days; 3 people; code produced by an AI agent with human auditing.
- Development in an Ubuntu VM in VirtualBox on a Windows PC; production on a small Linux VM in the cloud.
- Models are small and open (no API keys required at runtime). Quality of the model is not the point; isolation and evidence are.
- The kernel is shared by all containers; this is a documented residual risk.
- Market-size numbers are not used anywhere unless the team supplies a verified source.

## §10. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Timing signal too noisy in a VM | Long distinctive prefixes, `max_tokens=1`, 40 trials per condition, honest reporting, fallback to per-tenant model instances |
| llama.cpp slot behavior differs from assumptions | Verify first (T02), record in `docs/verified-notes.md`, fallback X-02 |
| Agent-written tests that prove nothing | Separate S-prompt sessions written from the spec; H-02 test-the-tests prompt |
| Over-scoping | Cut list in `docs/task.md`; never cut MUST items |
| Public site abused for CPU | Operator token for mutations, one active run, rate limits |
| Frontend late | Fallback UI in §6; API is stable and documented from Day 3 |

## §11. Alignment with the hackathon's six objectives

| Objective | Requirement IDs |
|---|---|
| 01 Isolate without breaking function | FR-01 to FR-05, FR-12 |
| 02 Prevent information leakage | FR-07, FR-08, FR-10, FR-18 to FR-20 |
| 03 Guarantee audit integrity | FR-13 to FR-17 |
| 04 Build for deployability | FR-26, FR-27, NFR-05 |
| 05 Address LLM-native threats | FR-18 to FR-20 |
| 06 Quantify residual risk | FR-16, threat model (architecture §12) |

## §12. Out of scope

User accounts, billing, multi-host orchestration, hardware-based isolation, GPU serving, custom model training, advanced anomaly detection, a full access-control policy engine, mobile apps, anything requiring paid APIs.
