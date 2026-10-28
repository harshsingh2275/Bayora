# Bayora Threat Model & Security Architecture

Bayora is an adversarial AI safety evaluation platform where three untrusted components run concurrently inside a shared Linux container environment:
1. **Red Team (Attacker):** Untrusted agent submitting adaptive or corpus-derived jailbreaks and prompt injections.
2. **Blue Team (Defender):** Untrusted agent deploying input/output regex filtering rules and safety refusal bundles.
3. **Target Model:** Isolated `llama.cpp` inference engine executing tenant requests.

This document formally specifies Bayora's threat model, the security invariants (SI-01 through SI-12) enforced and verified across the architecture, the cryptographic and runtime guarantees provided, and the **strict, honest limitations** of the system.

---

## 1. Verified Security Invariants (SI-01 through SI-12)

Every boundary in Bayora is anchored to twelve non-negotiable security invariants, verified by automated break-it probes and end-to-end integration test suites:

| Invariant | Name | Specification & Boundary Enforced | Verification Mechanism |
|---|---|---|---|
| **SI-01** | Zero Privileged Containers | No container is privileged. No `network_mode: host`, no `pid: host`, no `devices`, and no `/var/run/docker.sock` mount anywhere in the stack. | Break-it Probe C1; Docker inspect config audit asserts zero privileged containers and zero socket mounts. |
| **SI-02** | Least Privilege Container Runtime | Every custom container runs as an unprivileged user (`UID 10001:10001`), drops all Linux capabilities (`cap_drop: [ALL]`), sets `no-new-privileges: true`, mounts root as `read_only: true` with `tmpfs /tmp`, and enforces memory, CPU, and pids limits. | Break-it Probe C2 & C4; container execution tests assert capability escalation rejection and read-only filesystem barriers. |
| **SI-03** | Strict Network Partitions | `red-net`, `blue-net`, `model-red-net`, `model-blue-net`, and `log-net` are configured with `internal: true`. Tenants possess zero default gateway and zero internet access. Only the Gateway bridges tenant and backend networks. | Break-it Probes N1, N2, N3; DNS resolution and direct ping/HTTP cross-network probes strictly fail. |
| **SI-04** | Exclusive Gateway Mediation | The Gateway is the sole route to the target models and the only service authorized to communicate with the Audit Logger. Tenants never access models or the logger directly. | Break-it Probes N1, N3; network routing guarantees models and logger reject connections from non-gateway IPs. |
| **SI-05** | Constant-Time Token Validation | Tenant and admin authentication tokens are loaded as SHA-256 hashes inside Gateway memory, compared via `hmac.compare_digest` to prevent timing oracles, and never logged or returned. | Gateway authorization test suite; break-it Probe A1. |
| **SI-06** | Strict Request Schemas | Inbound API requests enforce Pydantic v2 `extra="forbid"`. Client-supplied model parameters (`id_slot`, `cache_prompt`, `temperature`, `max_tokens`) are strictly rejected. The Gateway builds all model requests itself. | Break-it Probes F1, F2; oversized or unauthorized field injection returns HTTP 422. |
| **SI-07** | Fail-Closed Audit Pipeline | If the Audit Logger service is unreachable, unresponsive, or reports an error, the Gateway immediately aborts the active operation and returns HTTP 503 Service Unavailable. | Gateway fail-closed integration test; logger termination triggers instant HTTP 503. |
| **SI-08** | Redaction Before Run Conclusion | Raw prompts, model responses, and defense rule bodies are cryptographically sealed before run conclusion. Mid-run audit entries record SHA-256 digests only. On public results endpoints, harmful AdvBench prompt text is strictly masked to `[PROMPT REDACTED FOR PUBLIC VIEW]`. Response headers (`timings`, `usage`, cache slots) are stripped. | Break-it Probe A5; public API privacy assertions verify zero prompt leaks in unauthenticated endpoints. |
| **SI-09** | Data-Only Defense Bundles | Blue defense bundles are declarative JSON data. Never `eval`, `exec`, import, or shell out on tenant content. All regex pattern matching is evaluated with strict timeouts (`regex.search(..., timeout=0.05)`). | ReDoS denial-of-service test suite; catastrophic backtracking regexes abort within 50ms without stalling the Gateway. |
| **SI-10** | Zero Secrets in Transit or Storage | Secrets never enter git, log streams, container images, or error messages. Managed via Docker secrets mounts (`/run/secrets/`). `.env`, `secrets/`, and runtime databases are gitignored. | Live log regex scan, git leak audit, break-it Probe L3. |
| **SI-11** | Public Proxy Surface Restriction | The public Caddy reverse proxy exposes `/api/*` endpoints only. All `/v1/*` tenant endpoints return HTTP 404 through `web`. Public endpoints are read-only; mutations require the operator bearer token. | Break-it Probe A2; external curls to `/v1/*` yield 404. |
| **SI-12** | Non-Negotiable Control Invariance | Security controls must never be weakened or bypassed to satisfy convenience or tests. Any security boundary conflict requires operator escalation. | Pre-commit architecture validation, break-it harness negative control demonstrations. |

---

## 2. Guaranteed Security Properties

Under the stated assumptions and architecture, Bayora guarantees:

1. **Pre-Conclusion Isolation:** Red cannot inspect Blue's active defense bundle, and Blue cannot inspect Red's attack prompts prior to run conclusion.
2. **Post-Commitment Input Immutability:** Tenants cannot alter their attack prompts or defense rules after the commitment phase without triggering cryptographic digest mismatch errors (HTTP 409).
3. **Direct Model Isolation:** Tenants cannot communicate directly with inference engines or manipulate inference parameters.
4. **Prefix-Cache Side-Channel Elimination (Isolated Mode):** By dedicating isolated inference model instances or pinned slots with KV-cache erasure upon conclusion, cross-tenant cache latency leakage is reduced below empirical detectability (Mann-Whitney U $p > 0.05$).
5. **Audit History Integrity:** Audit log entries are bound in a sequential SHA-256 hash chain with periodic signed Ed25519 checkpoints. History modifications, entry deletions, checkpoint forgeries, and intermediate truncations are caught by the independent Verifier.
6. **Public Data Protection:** Public API viewers cannot inspect raw harmful prompts from evaluation datasets; sensitive prompt text is replaced with uniform redaction markers while preserving exact cryptographic digests.

---

## 3. Strict Honest Limitations & Residual Risks

A credible security architecture must acknowledge what it **does not** protect against. Bayora operates with the following explicit, honest limitations:

### 3.1. Shared Linux Kernel Risks (Containers Are Not MicroVMs)
* **Risk:** All containers (`gateway`, `red`, `blue`, `model-red`, `model-blue`, `logger`, `verifier`, `web`) share a single Linux kernel on the host.
* **Limitation:** Linux namespaces and cgroups provide process boundary isolation, not hardware-level virtualization. A zero-day kernel privilege escalation (e.g., dirty COW, io_uring flaws) or container escape vulnerability allows an attacker to breach container boundaries, read host memory, or access neighboring tenant volumes.
* **Mitigation Boundary:** Mitigated to the extent possible via `cap_drop: [ALL]`, `no-new-privileges`, read-only filesystems, and strict seccomp filtering, but hardware hypervisors or microVMs (e.g., AWS Firecracker, Kata Containers, gVisor) would be required for true hardware isolation.

### 3.2. Absolute Trust in the Gateway and Logger (TCB Boundaries)
* **Risk:** The Gateway and Logger form the core Trusted Computing Base (TCB).
* **Limitation:** The Gateway is attached to multiple internal networks to orchestrate evaluation. If an attacker exploits a remote code execution vulnerability in the Gateway (e.g., Python runtime exploit or FastAPI dependency flaw), all tenant network boundaries collapse. Furthermore, while the Logger's hash chain guarantees tamper evidence for recorded entries, the Logger is trusted to honestly append records supplied by the Gateway.

### 3.3. Black-Box Behavioral Inference (Adaptive Oracle Feedback)
* **Risk:** Red can infer Blue's defense rules through repeated trial-and-error queries.
* **Limitation:** Cryptographic commit-reveal prevents Red from reading Blue's bundle JSON file before run conclusion. However, because Red receives discrete outcomes (`blocked_input`, `blocked_output`, `refused`, `complied`), an adaptive attacker can treat the Gateway as an oracle. By systematically probing keywords and variations, Red can reconstruct filtering heuristics through behavioral observation.

### 3.4. Shared CPU Timing & Hardware Contention (Microarchitectural Contention)
* **Risk:** Simultaneous execution causes CPU resource contention.
* **Limitation:** While Bayora's isolated cache mode successfully eliminates LLM KV prefix-cache side-channel leakage, Bayora does not mitigate shared CPU hardware contention. Co-located containers share CPU execution cores, L1/L2/L3 caches, and the memory bus. A compute-heavy burst from one tenant can cause measurable processing slowdowns for concurrent operations, creating a coarse timing channel.

### 3.5. Undetectable Log Tail Truncation After the Latest Checkpoint
* **Risk:** An adversary deleting the most recent log entries.
* **Limitation:** Bayora's audit log generates Ed25519 signed checkpoints every 10 entries and on demand. The independent verifier mathematically catches any intermediate deletion, entry tampering, or reordering. However, **tail truncation occurring after the most recent checkpoint is mathematically undetectable** from the log file alone unless the head hash has been witnessed and anchored by an external system (e.g., a public transparency log or an external operator anchor). This is an expected, documented limitation (Probe L2).

### 3.6. Measurement Topology (Host Loopback vs Public Network)
* **Risk:** Timing benchmark variance under real-world networking.
* **Limitation:** All empirical timing side-channel evaluations were conducted from the host operating system through `localhost` loopback routing. In a geographically distributed deployment, real-world network jitter, routing fluctuations, and TLS encryption overhead would add latency variance, potentially masking or distorting subtle microsecond-level timing differences.

### 3.7. Cloud Host Environment & Docker Daemon Permission Model
* **Cloud Infrastructure:** Hosted on Microsoft Azure Virtual Machines.
* **Host VM SKU:** `Standard_B2as_v2` (AMD EPYC 7763 64-Core Processor, 2 vCPUs, 8 GiB RAM).
* **Burstable CPU Behavior:** Azure B-series VMs operate on a fractional CPU baseline with burst credits. During heavy model inference, burst credits can become exhausted, resulting in hypervisor CPU throttling. This throttling can produce artificial latency spikes unrelated to tenant operations, increasing execution variance.
* **Docker Daemon Permission Model:** The host environment uses standard rootful Docker Engine (`dockerd` running as `root`), with container orchestration managed via the `docker` UNIX group. While containerized tenant processes run under unprivileged UIDs (`10001:10001`), the host Docker daemon possesses root capabilities. Compromise of the Docker socket or daemon control plane on the host would grant full administrative access.

---

## 4. Conditions Where Guarantees Fail

Bayora's security guarantees are predicated on defined operational boundaries. Guarantees fail if:
1. The host Linux kernel suffers an unpatched local privilege escalation exploit.
2. Operator authentication tokens are leaked or stored insecurely.
3. The Docker Compose configuration is modified to remove `internal: true` or restore Linux capabilities.
4. Upstream model server binaries (`llama-server`) alter slot allocation, prefix matching, or context management semantics without re-verification.
5. The Gateway fail-closed policy is intentionally disabled or bypassed.

---

## 5. Architectural Roadmap for Production Hardening

To elevate Bayora from a hardened multi-container architecture to multi-tenant production compliance:
* **MicroVM Sandboxing:** Transition tenant agents and inference instances into lightweight microVMs (Firecracker or Cloud Hypervisor) to eliminate shared kernel attack surfaces.
* **Rootless Container Engine:** Migrate the host orchestration layer to rootless Podman or Rootless Docker.
* **Public Notary Anchoring:** Publish signed checkpoint head hashes to an external, public append-only transparency ledger (e.g., Sigstore Rekor) to detect tail truncation.
* **Execution Jitter Injection & Latency Quantization:** Implement artificial response latency binning to eliminate microarchitectural CPU contention side-channels.
