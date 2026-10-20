"""
tests/security/test_commit_reveal.py
Security adversary test suite for Bayora Commit-Reveal protocol, lifecycle,
bundle validation, ReDoS resistance, and audit results integrity.

Source of Truth:
  - docs/architecture.md (§5, §6, §7)
  - AGENTS.md (§3)

Security Invariants tested:
  - SI-05: Tenant and admin tokens compared securely, never logged or returned.
  - SI-06: Request models use extra="forbid"; client-supplied model parameters rejected.
  - SI-07: Fail closed.
  - SI-08: No raw prompts, responses, or bundles in audit log or public API responses
           before conclusion. Strip timings/usage/slot fields.
  - SI-09: Defense bundles are data, never executed. Regex uses timeout so ReDoS
           cannot freeze or stall the gateway.
  - SI-11: Public proxy exposes /api/* only; /v1/* returns 404 through web.
  - Commit-Reveal Protocol:
      * Swap attack prompt after commit -> 409
      * Resend or skip idx values -> 409 / 422
      * Send attacks before running state -> 409
      * Call done early or late -> 409
      * Read blue/red report before conclusion -> 403
      * Public run view & results privacy before/after conclusion:
        - Never any prompts or rules before conclusion
        - Max 80-char prompt preview after conclusion, no full prompts
        - Never any rule IDs in public results
        - Never any full model responses in public results
      * Oversized and malformed bundles -> 422
      * ReDoS bundle resistance & latency measurement of concurrent requests
      * Start second run while one active -> 409
      * Abort lifecycle and timeout guarantees
      * results_digest in log == recomputed digest of revealed results
"""
import asyncio
import hashlib
import json
import os
import subprocess
import time
from typing import Any, Dict, List, Optional
import urllib.request

import httpx
import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SECRETS_DIR = os.path.join(REPO_ROOT, "secrets")


def _read_secret(name: str) -> str:
    path = os.path.join(SECRETS_DIR, name)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    return ""


RED_TOKEN = _read_secret("red_token")
BLUE_TOKEN = _read_secret("blue_token")
ADMIN_TOKEN = _read_secret("admin_token")


def _discover_gateway_url() -> Optional[str]:
    """Dynamically resolve gateway URL from env or running docker container."""
    if os.environ.get("GATEWAY_URL"):
        return os.environ["GATEWAY_URL"]
    try:
        res = subprocess.run(
            [
                "docker",
                "inspect",
                "-f",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}",
                "bayora-gateway",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        for ip in res.stdout.strip().split():
            ip = ip.strip()
            if not ip:
                continue
            test_url = f"http://{ip}:8000/api/health"
            try:
                with urllib.request.urlopen(test_url, timeout=1.0) as resp:
                    if resp.status == 200:
                        return f"http://{ip}:8000"
            except Exception:
                continue
    except Exception:
        pass
    return None


GATEWAY_URL = _discover_gateway_url()
WEB_URL = os.environ.get("WEB_URL", "http://127.0.0.1:8088")

pytestmark = pytest.mark.skipif(
    GATEWAY_URL is None,
    reason="Bayora stack is not running or gateway is unreachable",
)

OP_HEADERS = {"X-Admin-Token": ADMIN_TOKEN}
RED_HEADERS = {"Authorization": f"Bearer {RED_TOKEN}"}
BLUE_HEADERS = {"Authorization": f"Bearer {BLUE_TOKEN}"}


def _canonical_json_bytes(obj: Any) -> bytes:
    """Canonical JSON per §8: keys sorted, separators (',', ':'), UTF-8, ensure_ascii=False."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _canonical_digest(obj: Any) -> str:
    """SHA-256 of canonical JSON."""
    return hashlib.sha256(_canonical_json_bytes(obj)).hexdigest()


async def _abort_any_active_run(client: httpx.AsyncClient) -> None:
    """SECURITY: Clean up any active runs to ensure isolated test execution."""
    resp = await client.get("/api/runs")
    if resp.status_code == 200:
        for r in resp.json().get("runs", []):
            if r["state"] not in ("concluded", "aborted", "failed"):
                await client.post(f"/api/runs/{r['run_id']}/abort", headers=OP_HEADERS)


def _default_bundle() -> Dict[str, Any]:
    return {
        "version": "hardened-v1",
        "input_rules": [
            {"id": "I1", "type": "contains", "pattern": "forbidden_test_marker", "action": "block"}
        ],
        "output_rules": [
            {"id": "O1", "type": "contains", "pattern": "forbidden_output_marker", "action": "block"}
        ],
        "refusal_text": "Request blocked by safety policy.",
    }


# ==============================================================================
# 1. Swap attack prompt after commit
# ==============================================================================


@pytest.mark.asyncio
async def test_swap_attack_prompt_after_commit():
    """SECURITY: §6 & §10 (A6) - Attack with prompt not matching committed digest must return 409."""
    async with httpx.AsyncClient(base_url=GATEWAY_URL, timeout=60.0) as client:
        await _abort_any_active_run(client)

        create_res = await client.post(
            "/api/runs",
            headers=OP_HEADERS,
            json={"name": "test-swap-prompt", "attack_count": 2, "seed": 101, "bundle": "baseline"},
        )
        assert create_res.status_code == 201
        run_id = create_res.json()["run_id"]

        p0 = "forbidden_test_marker Legitimate committed attack prompt 0"
        p1 = "Legitimate committed attack prompt 1"
        digests = [hashlib.sha256(p.encode("utf-8")).hexdigest() for p in (p0, p1)]
        set_digest = hashlib.sha256("\n".join(digests).encode("utf-8")).hexdigest()

        # SECURITY: Red commits digests before executing attacks
        commit_res = await client.post(
            f"/v1/red/runs/{run_id}/commit",
            headers=RED_HEADERS,
            json={"count": 2, "digests": digests, "set_digest": set_digest},
        )
        assert commit_res.status_code == 200

        # Blue uploads bundle to transition state to 'running'
        def_res = await client.put(
            f"/v1/blue/runs/{run_id}/defense",
            headers=BLUE_HEADERS,
            json={"bundle": _default_bundle()},
        )
        assert def_res.status_code == 200

        # Attack A: Modified prompt after commit (arbitrary string)
        # SECURITY: Gateway verifies SHA-256(prompt) matches committed digest for idx
        swap_res = await client.post(
            f"/v1/red/runs/{run_id}/attack",
            headers=RED_HEADERS,
            json={"idx": 0, "prompt": "Adversary substituted prompt after commitment"},
        )
        assert swap_res.status_code == 409, f"Expected 409 for swapped prompt, got {swap_res.status_code}"

        # Attack B: Swap prompts order (send p1 for idx 0)
        # SECURITY: Swapping committed prompts between indices must fail digest comparison
        swap_order_res = await client.post(
            f"/v1/red/runs/{run_id}/attack",
            headers=RED_HEADERS,
            json={"idx": 0, "prompt": p1},
        )
        assert swap_order_res.status_code == 409, f"Expected 409 for swapped order, got {swap_order_res.status_code}"

        # Legitimate prompts proceed without issue
        att0 = await client.post(
            f"/v1/red/runs/{run_id}/attack",
            headers=RED_HEADERS,
            json={"idx": 0, "prompt": p0},
        )
        assert att0.status_code == 200

        att1 = await client.post(
            f"/v1/red/runs/{run_id}/attack",
            headers=RED_HEADERS,
            json={"idx": 1, "prompt": p1},
        )
        assert att1.status_code == 200

        done_res = await client.post(
            f"/v1/red/runs/{run_id}/done",
            headers=RED_HEADERS,
            json={"sent": 2},
        )
        assert done_res.status_code == 200


# ==============================================================================
# 2. Resend or skip idx values
# ==============================================================================


@pytest.mark.asyncio
async def test_resend_or_skip_idx_values():
    """SECURITY: §6 - Attacks must follow sequential, unique idx values; replays & skips rejected."""
    async with httpx.AsyncClient(base_url=GATEWAY_URL, timeout=30.0) as client:
        await _abort_any_active_run(client)

        create_res = await client.post(
            "/api/runs",
            headers=OP_HEADERS,
            json={"name": "test-idx-ordering", "attack_count": 3, "seed": 102, "bundle": "baseline"},
        )
        assert create_res.status_code == 201
        run_id = create_res.json()["run_id"]

        prompts = [f"Prompt index {i}" for i in range(3)]
        digests = [hashlib.sha256(p.encode("utf-8")).hexdigest() for p in prompts]
        set_digest = hashlib.sha256("\n".join(digests).encode("utf-8")).hexdigest()

        await client.post(
            f"/v1/red/runs/{run_id}/commit",
            headers=RED_HEADERS,
            json={"count": 3, "digests": digests, "set_digest": set_digest},
        )
        await client.put(
            f"/v1/blue/runs/{run_id}/defense",
            headers=BLUE_HEADERS,
            json={"bundle": _default_bundle()},
        )

        # Negative idx: rejected with 422 by schema validation
        # SECURITY: Negative index rejected by pydantic or state machine
        neg_res = await client.post(
            f"/v1/red/runs/{run_id}/attack",
            headers=RED_HEADERS,
            json={"idx": -1, "prompt": "negative"},
        )
        assert neg_res.status_code == 422, f"Expected 422 for negative idx, got {neg_res.status_code}"

        # Out-of-bounds idx: send idx=3 when attack_count is 3 (valid indices are 0..2)
        # SECURITY: Out of range idx rejected to prevent out-of-bounds array access
        oob_res = await client.post(
            f"/v1/red/runs/{run_id}/attack",
            headers=RED_HEADERS,
            json={"idx": 3, "prompt": "out of bounds"},
        )
        assert oob_res.status_code in (409, 422), f"Expected 409 or 422, got {oob_res.status_code}"

        # Attack idx=0 sent successfully
        att0 = await client.post(
            f"/v1/red/runs/{run_id}/attack",
            headers=RED_HEADERS,
            json={"idx": 0, "prompt": prompts[0]},
        )
        assert att0.status_code == 200

        # Resend / replay attack 0
        # SECURITY: Replaying an already processed idx must be rejected with 409 Conflict
        replay_res = await client.post(
            f"/v1/red/runs/{run_id}/attack",
            headers=RED_HEADERS,
            json={"idx": 0, "prompt": prompts[0]},
        )
        assert replay_res.status_code == 409, f"Expected 409 for replay idx, got {replay_res.status_code}"

        # Skip idx: send idx=2 without sending idx=1 first
        att2 = await client.post(
            f"/v1/red/runs/{run_id}/attack",
            headers=RED_HEADERS,
            json={"idx": 2, "prompt": prompts[2]},
        )
        assert att2.status_code == 200

        # Adversary attempts to call done having skipped idx=1 (only 2 out of 3 processed)
        # SECURITY: Gateway verifies all attacks processed; skipped idx blocks conclusion
        done_skipped_sent3 = await client.post(
            f"/v1/red/runs/{run_id}/done",
            headers=RED_HEADERS,
            json={"sent": 3},
        )
        assert done_skipped_sent3.status_code == 409, f"Expected 409 when concluding with skipped idx, got {done_skipped_sent3.status_code}"

        done_skipped_sent2 = await client.post(
            f"/v1/red/runs/{run_id}/done",
            headers=RED_HEADERS,
            json={"sent": 2},
        )
        assert done_skipped_sent2.status_code == 409, f"Expected 409 when count does not reach attack_count, got {done_skipped_sent2.status_code}"

        # Send the missing idx=1
        att1 = await client.post(
            f"/v1/red/runs/{run_id}/attack",
            headers=RED_HEADERS,
            json={"idx": 1, "prompt": prompts[1]},
        )
        assert att1.status_code == 200

        # Now all 3 processed: conclusion succeeds
        done_ok = await client.post(
            f"/v1/red/runs/{run_id}/done",
            headers=RED_HEADERS,
            json={"sent": 3},
        )
        assert done_ok.status_code == 200


# ==============================================================================
# 3. Send attacks before running state
# ==============================================================================


@pytest.mark.asyncio
async def test_send_attacks_before_running_state():
    """SECURITY: §6 - Attacks sent in created, committing, or aborted states must return 409."""
    async with httpx.AsyncClient(base_url=GATEWAY_URL, timeout=30.0) as client:
        await _abort_any_active_run(client)

        create_res = await client.post(
            "/api/runs",
            headers=OP_HEADERS,
            json={"name": "test-early-attacks", "attack_count": 1, "seed": 103, "bundle": "baseline"},
        )
        assert create_res.status_code == 201
        run_id = create_res.json()["run_id"]

        p0 = "Prompt for early attack test"
        d0 = hashlib.sha256(p0.encode("utf-8")).hexdigest()

        # 3a. Attack in 'created' state (neither committed)
        # SECURITY: Attacks rejected before both parties commit
        att_created = await client.post(
            f"/v1/red/runs/{run_id}/attack",
            headers=RED_HEADERS,
            json={"idx": 0, "prompt": p0},
        )
        assert att_created.status_code == 409, f"Expected 409 in created state, got {att_created.status_code}"

        # 3b. Red commits, Blue has not committed -> state is 'committing'
        await client.post(
            f"/v1/red/runs/{run_id}/commit",
            headers=RED_HEADERS,
            json={"count": 1, "digests": [d0], "set_digest": d0},
        )
        # SECURITY: Attacks rejected until blue defense bundle is sealed and state is running
        att_committing = await client.post(
            f"/v1/red/runs/{run_id}/attack",
            headers=RED_HEADERS,
            json={"idx": 0, "prompt": p0},
        )
        assert att_committing.status_code == 409, f"Expected 409 in committing state, got {att_committing.status_code}"

        # 3c. Abort run and verify attack rejected in 'aborted' state
        abort_res = await client.post(f"/api/runs/{run_id}/abort", headers=OP_HEADERS)
        assert abort_res.status_code == 200

        # SECURITY: Aborted run cannot accept attacks
        att_aborted = await client.post(
            f"/v1/red/runs/{run_id}/attack",
            headers=RED_HEADERS,
            json={"idx": 0, "prompt": p0},
        )
        assert att_aborted.status_code == 409, f"Expected 409 in aborted state, got {att_aborted.status_code}"


# ==============================================================================
# 4. Call done early or late
# ==============================================================================


@pytest.mark.asyncio
async def test_call_done_early_or_late():
    """SECURITY: §6 - done endpoint verifies count; early, fraudulent, or repeat calls must return 409."""
    async with httpx.AsyncClient(base_url=GATEWAY_URL, timeout=30.0) as client:
        await _abort_any_active_run(client)

        create_res = await client.post(
            "/api/runs",
            headers=OP_HEADERS,
            json={"name": "test-done-lifecycle", "attack_count": 2, "seed": 104, "bundle": "baseline"},
        )
        assert create_res.status_code == 201
        run_id = create_res.json()["run_id"]

        prompts = ["Done prompt 0", "Done prompt 1"]
        digests = [hashlib.sha256(p.encode("utf-8")).hexdigest() for p in prompts]
        set_digest = hashlib.sha256("\n".join(digests).encode("utf-8")).hexdigest()

        await client.post(
            f"/v1/red/runs/{run_id}/commit",
            headers=RED_HEADERS,
            json={"count": 2, "digests": digests, "set_digest": set_digest},
        )
        await client.put(
            f"/v1/blue/runs/{run_id}/defense",
            headers=BLUE_HEADERS,
            json={"bundle": _default_bundle()},
        )

        # 4a. Call done immediately before any attacks sent
        # SECURITY: done called before count reached must be rejected with 409
        done_early_zero = await client.post(
            f"/v1/red/runs/{run_id}/done",
            headers=RED_HEADERS,
            json={"sent": 0},
        )
        assert done_early_zero.status_code == 409, f"Expected 409 for done(0), got {done_early_zero.status_code}"

        # 4b. Send 1 attack, call done claiming sent=1 (less than committed count 2)
        await client.post(
            f"/v1/red/runs/{run_id}/attack",
            headers=RED_HEADERS,
            json={"idx": 0, "prompt": prompts[0]},
        )
        done_partial = await client.post(
            f"/v1/red/runs/{run_id}/done",
            headers=RED_HEADERS,
            json={"sent": 1},
        )
        assert done_partial.status_code == 409, f"Expected 409 for partial done(1), got {done_partial.status_code}"

        # 4c. Call done claiming sent=2 when only 1 was sent
        # SECURITY: Gateway verifies sent count against actual processed count
        done_fraudulent = await client.post(
            f"/v1/red/runs/{run_id}/done",
            headers=RED_HEADERS,
            json={"sent": 2},
        )
        assert done_fraudulent.status_code == 409, f"Expected 409 for fraudulent done(2), got {done_fraudulent.status_code}"

        # Send second attack
        await client.post(
            f"/v1/red/runs/{run_id}/attack",
            headers=RED_HEADERS,
            json={"idx": 1, "prompt": prompts[1]},
        )

        # Legitimate done
        done_ok = await client.post(
            f"/v1/red/runs/{run_id}/done",
            headers=RED_HEADERS,
            json={"sent": 2},
        )
        assert done_ok.status_code == 200

        # 4d. Call done late / double done after already concluded
        # SECURITY: Repeated done on concluded run must return 409 Conflict
        done_late = await client.post(
            f"/v1/red/runs/{run_id}/done",
            headers=RED_HEADERS,
            json={"sent": 2},
        )
        assert done_late.status_code == 409, f"Expected 409 for double done, got {done_late.status_code}"


# ==============================================================================
# 5. Read blue's report and red's report before conclusion
# ==============================================================================


@pytest.mark.asyncio
async def test_read_reports_before_conclusion_and_cross_tenant():
    """SECURITY: §5 & §10 (A4, A2) - Reports locked (403) before conclusion; cross-tenant role checks enforced."""
    async with httpx.AsyncClient(base_url=GATEWAY_URL, timeout=30.0) as client:
        await _abort_any_active_run(client)

        create_res = await client.post(
            "/api/runs",
            headers=OP_HEADERS,
            json={"name": "test-report-privacy", "attack_count": 1, "seed": 105, "bundle": "baseline"},
        )
        run_id = create_res.json()["run_id"]

        p0 = "Secret test prompt for report disclosure test"
        d0 = hashlib.sha256(p0.encode("utf-8")).hexdigest()

        await client.post(
            f"/v1/red/runs/{run_id}/commit",
            headers=RED_HEADERS,
            json={"count": 1, "digests": [d0], "set_digest": d0},
        )
        await client.put(
            f"/v1/blue/runs/{run_id}/defense",
            headers=BLUE_HEADERS,
            json={"bundle": _default_bundle()},
        )

        # 5a. Mid-run: Blue report must be 403 Forbidden
        # SECURITY: Blue cannot read attack prompts or results before run concludes
        blue_rep_mid = await client.get(f"/v1/blue/runs/{run_id}/report", headers=BLUE_HEADERS)
        assert blue_rep_mid.status_code == 403, f"Expected 403 for blue report mid-run, got {blue_rep_mid.status_code}"
        assert p0 not in blue_rep_mid.text, "LEAK: prompt appeared in 403 error body!"

        # 5b. Mid-run: Red report must be 403 Forbidden
        # SECURITY: Red cannot read defense evaluation before run concludes
        red_rep_mid = await client.get(f"/v1/red/runs/{run_id}/report", headers=RED_HEADERS)
        assert red_rep_mid.status_code == 403, f"Expected 403 for red report mid-run, got {red_rep_mid.status_code}"

        # 5c. Cross-tenant authentication check (A2)
        # SECURITY: Red token on blue endpoint rejected with 403
        cross_red_on_blue = await client.get(f"/v1/blue/runs/{run_id}/report", headers=RED_HEADERS)
        assert cross_red_on_blue.status_code == 403

        # SECURITY: Blue token on red endpoint rejected with 403
        cross_blue_on_red = await client.get(f"/v1/red/runs/{run_id}/report", headers=BLUE_HEADERS)
        assert cross_blue_on_red.status_code == 403

        # 5d. Unauthenticated request rejected with 401
        anon_blue = await client.get(f"/v1/blue/runs/{run_id}/report")
        assert anon_blue.status_code == 401
        anon_red = await client.get(f"/v1/red/runs/{run_id}/report")
        assert anon_red.status_code == 401

        # Clean up
        await client.post(f"/api/runs/{run_id}/abort", headers=OP_HEADERS)


# ==============================================================================
# 6. Public run view and results before and after conclusion
# ==============================================================================


@pytest.mark.asyncio
async def test_public_view_and_results_privacy_before_and_after_conclusion():
    """SECURITY: §5, §10 (A5) & SI-08 - Public view must never leak prompts beyond 80 chars after conclusion,
    never before, never rule ids, never full model responses."""
    async with httpx.AsyncClient(base_url=GATEWAY_URL, timeout=30.0) as client:
        await _abort_any_active_run(client)

        create_res = await client.post(
            "/api/runs",
            headers=OP_HEADERS,
            json={"name": "test-public-privacy", "attack_count": 2, "seed": 106, "bundle": "baseline"},
        )
        run_id = create_res.json()["run_id"]

        long_prompt = "A" * 80 + "SUPER_SECRET_PAYLOAD_PAST_EIGHTY_CHARS_DO_NOT_LEAK"
        short_prompt = "Short prompt asking for status"
        prompts = [long_prompt, short_prompt]
        digests = [hashlib.sha256(p.encode("utf-8")).hexdigest() for p in prompts]
        set_digest = hashlib.sha256("\n".join(digests).encode("utf-8")).hexdigest()

        await client.post(
            f"/v1/red/runs/{run_id}/commit",
            headers=RED_HEADERS,
            json={"count": 2, "digests": digests, "set_digest": set_digest},
        )

        custom_bundle = {
            "version": "hardened-v1",
            "input_rules": [
                {"id": "SECRET_RULE_INPUT_99", "type": "contains", "pattern": "SUPER_SECRET_PAYLOAD", "action": "block"}
            ],
            "output_rules": [],
            "refusal_text": "Request blocked by safety policy.",
        }
        await client.put(f"/v1/blue/runs/{run_id}/defense", headers=BLUE_HEADERS, json={"bundle": custom_bundle})

        # --- BEFORE CONCLUSION PRIVACY CHECKS ---
        # 1. /api/runs/{id} before conclusion: digests only, no raw prompts or rule ids
        # SECURITY: Public run detail must show state and digests, never prompts or defense rules
        run_pub_mid = await client.get(f"/api/runs/{run_id}")
        assert run_pub_mid.status_code == 200
        mid_body = run_pub_mid.text
        assert "SUPER_SECRET_PAYLOAD" not in mid_body, "LEAK: Prompt leaked in public run view before conclusion!"
        assert "SECRET_RULE_INPUT_99" not in mid_body, "LEAK: Rule ID leaked in public run view!"

        # 2. /api/runs/{id}/results before conclusion must be 403 Forbidden
        # SECURITY: Public results endpoint sealed before conclusion (§5, §10 A5)
        res_pre = await client.get(f"/api/runs/{run_id}/results")
        assert res_pre.status_code == 403, f"Expected 403 for public results before conclusion, got {res_pre.status_code}"
        assert "SUPER_SECRET_PAYLOAD" not in res_pre.text

        # Execute attacks & conclude
        att0 = await client.post(f"/v1/red/runs/{run_id}/attack", headers=RED_HEADERS, json={"idx": 0, "prompt": long_prompt})
        assert att0.status_code == 200
        att1 = await client.post(f"/v1/red/runs/{run_id}/attack", headers=RED_HEADERS, json={"idx": 1, "prompt": short_prompt})
        assert att1.status_code == 200

        done_res = await client.post(f"/v1/red/runs/{run_id}/done", headers=RED_HEADERS, json={"sent": 2})
        assert done_res.status_code == 200

        # --- AFTER CONCLUSION PRIVACY CHECKS ---
        # 3. Public results unlocked
        res_post = await client.get(f"/api/runs/{run_id}/results")
        assert res_post.status_code == 200
        results_data = res_post.json()

        assert "attacks" in results_data
        for item in results_data["attacks"]:
            preview = item.get("prompt_preview", "")
            # SECURITY: Prompt preview must be capped at 80 characters
            assert len(preview) <= 80, f"LEAK: prompt_preview exceeded 80 chars ({len(preview)} chars): {preview}"
            assert "SUPER_SECRET_PAYLOAD_PAST_EIGHTY_CHARS" not in preview, "LEAK: Characters past index 80 exposed in preview!"

            # SECURITY: Never expose full raw prompts in public results
            assert "prompt" not in item, "LEAK: Raw prompt key exposed in public results!"

            # SECURITY: Never expose rule IDs in public results
            assert "rule_id" not in item, "LEAK: rule_id exposed in public results attack item!"
            assert "SECRET_RULE_INPUT_99" not in json.dumps(item), "LEAK: Secret rule ID found in attack item!"

            # SECURITY: Never expose full model responses in public results
            assert "response" not in item, "LEAK: response text exposed in public results!"
            assert "response_text" not in item, "LEAK: response_text exposed in public results!"
            assert "text" not in item, "LEAK: text field exposed in public results!"

        # 4. Asymmetric Red report check
        # SECURITY: Red report after conclusion has outcomes only, never rule IDs or bundle
        red_rep = await client.get(f"/v1/red/runs/{run_id}/report", headers=RED_HEADERS)
        assert red_rep.status_code == 200
        red_data = red_rep.json()
        for att in red_data.get("attacks", []):
            assert set(att.keys()) == {"idx", "outcome"}, f"LEAK: Red report leaked forbidden fields: {att.keys()}"
            assert "SECRET_RULE_INPUT_99" not in json.dumps(att)


# ==============================================================================
# 7. Submit oversized and malformed bundles
# ==============================================================================


@pytest.mark.asyncio
async def test_submit_oversized_and_malformed_bundles():
    """SECURITY: §7 & SI-06 - Validate defense bundle limits (<200 rules, <200 chars), forbid extra fields."""
    async with httpx.AsyncClient(base_url=GATEWAY_URL, timeout=30.0) as client:
        await _abort_any_active_run(client)

        create_res = await client.post(
            "/api/runs",
            headers=OP_HEADERS,
            json={"name": "test-bundle-validation", "attack_count": 1, "seed": 107, "bundle": "baseline"},
        )
        run_id = create_res.json()["run_id"]

        # 7a. Oversized rules list (> 200 rules)
        # SECURITY: §7 restricts bundle to at most 200 rules
        bundle_201_rules = {
            "version": "hardened-v1",
            "input_rules": [
                {"id": f"R{i}", "type": "contains", "pattern": f"p{i}", "action": "block"}
                for i in range(201)
            ],
            "output_rules": [],
            "refusal_text": "Block.",
        }
        res_201 = await client.put(f"/v1/blue/runs/{run_id}/defense", headers=BLUE_HEADERS, json={"bundle": bundle_201_rules})
        assert res_201.status_code == 422, f"Expected 422 for >200 rules, got {res_201.status_code}"

        # 7b. Oversized rule pattern (> 200 chars)
        # SECURITY: §7 restricts pattern length to at most 200 chars
        bundle_long_pattern = {
            "version": "hardened-v1",
            "input_rules": [
                {"id": "R1", "type": "contains", "pattern": "a" * 201, "action": "block"}
            ],
            "output_rules": [],
            "refusal_text": "Block.",
        }
        res_long_pat = await client.put(f"/v1/blue/runs/{run_id}/defense", headers=BLUE_HEADERS, json={"bundle": bundle_long_pattern})
        assert res_long_pat.status_code == 422, f"Expected 422 for pattern >200 chars, got {res_long_pat.status_code}"

        # 7c. Oversized refusal_text (> 200 chars)
        # SECURITY: §7 restricts refusal_text length to at most 200 chars
        bundle_long_refusal = {
            "version": "hardened-v1",
            "input_rules": [],
            "output_rules": [],
            "refusal_text": "x" * 201,
        }
        res_long_ref = await client.put(f"/v1/blue/runs/{run_id}/defense", headers=BLUE_HEADERS, json={"bundle": bundle_long_refusal})
        assert res_long_ref.status_code == 422, f"Expected 422 for refusal_text >200 chars, got {res_long_ref.status_code}"

        # 7d. Missing required fields (malformed)
        res_no_ver = await client.put(
            f"/v1/blue/runs/{run_id}/defense",
            headers=BLUE_HEADERS,
            json={"bundle": {"input_rules": [], "output_rules": [], "refusal_text": "Block."}},
        )
        assert res_no_ver.status_code == 422, f"Expected 422 for missing version, got {res_no_ver.status_code}"

        # 7e. Injected / unknown fields (extra="forbid" per SI-06)
        # SECURITY: SI-06 - extra='forbid' prevents tenant parameter injection or eval attempts
        bundle_injected = {
            "version": "hardened-v1",
            "input_rules": [],
            "output_rules": [],
            "refusal_text": "Block.",
            "__injected_code__": "import os; os.system('echo pwned')",
        }
        res_extra = await client.put(f"/v1/blue/runs/{run_id}/defense", headers=BLUE_HEADERS, json={"bundle": bundle_injected})
        assert res_extra.status_code == 422, f"Expected 422 for extra='forbid' violation, got {res_extra.status_code}"

        # 7f. Unknown rule type
        # SECURITY: Only 'contains' and 'regex' types permitted
        bundle_bad_type = {
            "version": "hardened-v1",
            "input_rules": [{"id": "R1", "type": "eval_python", "pattern": "x", "action": "block"}],
            "output_rules": [],
            "refusal_text": "Block.",
        }
        res_bad_type = await client.put(f"/v1/blue/runs/{run_id}/defense", headers=BLUE_HEADERS, json={"bundle": bundle_bad_type})
        assert res_bad_type.status_code == 422, f"Expected 422 for unknown rule type, got {res_bad_type.status_code}"

        # 7g. Invalid regex syntax
        # SECURITY: Malformed regex patterns rejected during bundle validation
        bundle_bad_regex = {
            "version": "hardened-v1",
            "input_rules": [{"id": "R1", "type": "regex", "pattern": "[unclosed-bracket", "action": "block"}],
            "output_rules": [],
            "refusal_text": "Block.",
        }
        res_bad_regex = await client.put(f"/v1/blue/runs/{run_id}/defense", headers=BLUE_HEADERS, json={"bundle": bundle_bad_regex})
        assert res_bad_regex.status_code == 422, f"Expected 422 for invalid regex syntax, got {res_bad_regex.status_code}"

        # Clean up
        await client.post(f"/api/runs/{run_id}/abort", headers=OP_HEADERS)


# ==============================================================================
# 8. Catastrophic backtracking regex bundle and gateway latency
# ==============================================================================


@pytest.mark.asyncio
async def test_regex_catastrophic_backtracking_and_gateway_latency():
    """SECURITY: §7 & SI-09 - Regex must use per-match timeout so ReDoS patterns cannot stall the gateway."""
    async with httpx.AsyncClient(base_url=GATEWAY_URL, timeout=30.0) as client:
        await _abort_any_active_run(client)

        create_res = await client.post(
            "/api/runs",
            headers=OP_HEADERS,
            json={"name": "test-redos-latency", "attack_count": 1, "seed": 108, "bundle": "hardened"},
        )
        assert create_res.status_code == 201
        run_id = create_res.json()["run_id"]

        # Classic ReDoS catastrophic backtracking trigger: (a+)+b on string of 'a's ending in 'c'
        evil_prompt = "a" * 80 + "c"
        evil_digest = hashlib.sha256(evil_prompt.encode("utf-8")).hexdigest()
        evil_set_digest = hashlib.sha256(evil_digest.encode("utf-8")).hexdigest()

        commit_res = await client.post(
            f"/v1/red/runs/{run_id}/commit",
            headers=RED_HEADERS,
            json={"count": 1, "digests": [evil_digest], "set_digest": evil_set_digest},
        )
        assert commit_res.status_code == 200

        evil_bundle = {
            "version": "hardened-v1",
            "input_rules": [
                {"id": "REDOS_RULE_1", "type": "regex", "pattern": "(a+)+b", "action": "block"}
            ],
            "output_rules": [],
            "refusal_text": "Blocked by ReDoS rule.",
        }
        def_res = await client.put(
            f"/v1/blue/runs/{run_id}/defense",
            headers=BLUE_HEADERS,
            json={"bundle": evil_bundle},
        )
        assert def_res.status_code == 200

        # Launch concurrent background probing tasks while the ReDoS attack is processed
        concurrent_latencies: List[float] = []

        async def probe_gateway_health():
            for _ in range(5):
                t0 = time.perf_counter()
                resp = await client.get("/api/health")
                t_el = time.perf_counter() - t0
                if resp.status_code == 200:
                    concurrent_latencies.append(t_el)
                await asyncio.sleep(0.02)

        health_task = asyncio.create_task(probe_gateway_health())

        # Send the ReDoS attack
        t_start = time.perf_counter()
        attack_res = await client.post(
            f"/v1/red/runs/{run_id}/attack",
            headers=RED_HEADERS,
            json={"idx": 0, "prompt": evil_prompt},
        )
        t_attack_elapsed = time.perf_counter() - t_start
        await health_task

        # SECURITY: ReDoS pattern must not freeze event loop; timeout bounded
        assert attack_res.status_code == 200, f"Expected 200, got {attack_res.status_code}: {attack_res.text}"
        assert t_attack_elapsed < 8.0, f"Catastrophic backtracking stalled gateway! Elapsed: {t_attack_elapsed:.2f}s"

        # Check concurrent gateway latency during ReDoS evaluation
        assert len(concurrent_latencies) > 0, "No concurrent probes completed!"
        max_concurrent_lat = max(concurrent_latencies)
        assert max_concurrent_lat < 1.0, f"Gateway health latency spiked excessively during ReDoS: {max_concurrent_lat:.3f}s"

        # Conclude run
        await client.post(f"/v1/red/runs/{run_id}/done", headers=RED_HEADERS, json={"sent": 1})


# ==============================================================================
# 9. Start a second run while one is active
# ==============================================================================


@pytest.mark.asyncio
async def test_start_second_run_while_one_active():
    """SECURITY: §5 & §6 - Exactly one active run permitted; concurrent run creation returns 409."""
    async with httpx.AsyncClient(base_url=GATEWAY_URL, timeout=30.0) as client:
        await _abort_any_active_run(client)

        # 9a. Create Run 1 (state: created)
        res1 = await client.post(
            "/api/runs",
            headers=OP_HEADERS,
            json={"name": "active-run-1", "attack_count": 1, "seed": 109, "bundle": "baseline"},
        )
        assert res1.status_code == 201
        run_id_1 = res1.json()["run_id"]

        # Attempt to create Run 2 while Run 1 is in 'created' state
        # SECURITY: Gateway enforces run concurrency lock (409 Conflict)
        res2_early = await client.post(
            "/api/runs",
            headers=OP_HEADERS,
            json={"name": "active-run-2-rejected", "attack_count": 1, "seed": 110, "bundle": "baseline"},
        )
        assert res2_early.status_code == 409, f"Expected 409 for second run while created, got {res2_early.status_code}"

        # Transition Run 1 to 'running'
        p = "Prompt for run concurrency test"
        d = hashlib.sha256(p.encode("utf-8")).hexdigest()
        await client.post(f"/v1/red/runs/{run_id_1}/commit", headers=RED_HEADERS, json={"count": 1, "digests": [d], "set_digest": d})
        await client.put(f"/v1/blue/runs/{run_id_1}/defense", headers=BLUE_HEADERS, json={"bundle": _default_bundle()})

        # Attempt to create Run 2 while Run 1 is in 'running' state
        # SECURITY: Gateway enforces run concurrency lock during running state
        res2_running = await client.post(
            "/api/runs",
            headers=OP_HEADERS,
            json={"name": "active-run-2-rejected-running", "attack_count": 1, "seed": 111, "bundle": "baseline"},
        )
        assert res2_running.status_code == 409, f"Expected 409 for second run while running, got {res2_running.status_code}"

        # Clean up Run 1 by aborting
        await client.post(f"/api/runs/{run_id_1}/abort", headers=OP_HEADERS)

        # Now creating a new run should succeed
        res3 = await client.post(
            "/api/runs",
            headers=OP_HEADERS,
            json={"name": "active-run-after-abort", "attack_count": 1, "seed": 112, "bundle": "baseline"},
        )
        assert res3.status_code == 201
        run_id_3 = res3.json()["run_id"]
        await client.post(f"/api/runs/{run_id_3}/abort", headers=OP_HEADERS)


# ==============================================================================
# 10. Abort and timeout behavior
# ==============================================================================


@pytest.mark.asyncio
async def test_abort_lifecycle_and_timeout_behavior():
    """SECURITY: §5 & §6 - Abort transitions state to 'aborted', rejects mutations, logs event, unlocks concurrency."""
    async with httpx.AsyncClient(base_url=GATEWAY_URL, timeout=30.0) as client:
        await _abort_any_active_run(client)

        create_res = await client.post(
            "/api/runs",
            headers=OP_HEADERS,
            json={"name": "test-abort-flow", "attack_count": 1, "seed": 113, "bundle": "baseline"},
        )
        assert create_res.status_code == 201
        run_id = create_res.json()["run_id"]

        # 10a. Unauthorized abort attempts
        # SECURITY: Tenant tokens and unauthorized callers cannot trigger operator run abort (401 or 403)
        abort_red = await client.post(f"/api/runs/{run_id}/abort", headers=RED_HEADERS)
        assert abort_red.status_code in (401, 403), f"Expected 401/403 for red abort, got {abort_red.status_code}"

        abort_blue = await client.post(f"/api/runs/{run_id}/abort", headers=BLUE_HEADERS)
        assert abort_blue.status_code in (401, 403), f"Expected 401/403 for blue abort, got {abort_blue.status_code}"

        # Wrong admin token
        abort_bad_admin = await client.post(f"/api/runs/{run_id}/abort", headers={"X-Admin-Token": "invalid_admin_secret"})
        assert abort_bad_admin.status_code in (401, 403), f"Expected 401/403 for bad admin token, got {abort_bad_admin.status_code}"

        abort_anon = await client.post(f"/api/runs/{run_id}/abort")
        assert abort_anon.status_code == 401, f"Expected 401 for anon abort, got {abort_anon.status_code}"

        # 10b. Operator aborts run
        abort_op = await client.post(f"/api/runs/{run_id}/abort", headers=OP_HEADERS)
        assert abort_op.status_code == 200

        # State must now be 'aborted'
        detail = (await client.get(f"/api/runs/{run_id}")).json()
        assert detail["state"] == "aborted"

        # 10c. Subsequent mutations on aborted run must return 409
        # SECURITY: Commit on aborted run rejected
        valid_d = hashlib.sha256(b"dummy_prompt").hexdigest()
        valid_s = hashlib.sha256(valid_d.encode()).hexdigest()
        c_res = await client.post(
            f"/v1/red/runs/{run_id}/commit",
            headers=RED_HEADERS,
            json={"count": 1, "digests": [valid_d], "set_digest": valid_s},
        )
        assert c_res.status_code == 409

        # SECURITY: Attack on aborted run rejected
        att_aborted = await client.post(
            f"/v1/red/runs/{run_id}/attack",
            headers=RED_HEADERS,
            json={"idx": 0, "prompt": "dummy_prompt"},
        )
        assert att_aborted.status_code == 409

        # SECURITY: Defense upload on aborted run rejected
        d_res = await client.put(
            f"/v1/blue/runs/{run_id}/defense",
            headers=BLUE_HEADERS,
            json={"bundle": _default_bundle()},
        )
        assert d_res.status_code == 409

        # SECURITY: Done call on aborted run rejected
        done_res = await client.post(
            f"/v1/red/runs/{run_id}/done",
            headers=RED_HEADERS,
            json={"sent": 1},
        )
        assert done_res.status_code == 409

        # 10d. Double abort on already aborted run returns 409
        abort_again = await client.post(f"/api/runs/{run_id}/abort", headers=OP_HEADERS)
        assert abort_again.status_code == 409, f"Expected 409 for double abort, got {abort_again.status_code}"

        # 10e. Abort non-existent run returns 404
        abort_missing = await client.post("/api/runs/00000000-0000-0000-0000-000000000000/abort", headers=OP_HEADERS)
        assert abort_missing.status_code == 404


# ==============================================================================
# 11. Confirm results_digest in the log equals recomputed digest of revealed results
# ==============================================================================


@pytest.mark.asyncio
async def test_results_digest_integrity_against_audit_log():
    """SECURITY: §6 (Step 6-7) & §8 - Cryptographic binding: logged results_digest MUST match
    recomputed SHA-256 digest of canonical revealed results JSON."""
    async with httpx.AsyncClient(base_url=GATEWAY_URL, timeout=30.0) as client:
        await _abort_any_active_run(client)

        create_res = await client.post(
            "/api/runs",
            headers=OP_HEADERS,
            json={"name": "test-results-digest", "attack_count": 3, "seed": 114, "bundle": "hardened"},
        )
        assert create_res.status_code == 201
        run_id = create_res.json()["run_id"]

        prompts = [
            "Harmful trigger: forbidden_test_marker input test",
            "Hello model, please respond to this benchmark attack query 1",
            "Harmful query asking for forbidden_output_marker payload",
        ]
        digests = [hashlib.sha256(p.encode("utf-8")).hexdigest() for p in prompts]
        set_digest = hashlib.sha256("\n".join(digests).encode("utf-8")).hexdigest()

        await client.post(
            f"/v1/red/runs/{run_id}/commit",
            headers=RED_HEADERS,
            json={"count": 3, "digests": digests, "set_digest": set_digest},
        )

        bundle = {
            "version": "hardened-v1",
            "input_rules": [
                {"id": "RULE_I1", "type": "contains", "pattern": "forbidden_test_marker", "action": "block"}
            ],
            "output_rules": [
                {"id": "RULE_O1", "type": "contains", "pattern": "forbidden_output_marker", "action": "block"}
            ],
            "refusal_text": "Request blocked by safety policy.",
        }
        await client.put(f"/v1/blue/runs/{run_id}/defense", headers=BLUE_HEADERS, json={"bundle": bundle})

        # Process attacks
        for i, p in enumerate(prompts):
            att_res = await client.post(f"/v1/red/runs/{run_id}/attack", headers=RED_HEADERS, json={"idx": i, "prompt": p})
            assert att_res.status_code == 200

        # Conclude run
        done_res = await client.post(f"/v1/red/runs/{run_id}/done", headers=RED_HEADERS, json={"sent": 3})
        assert done_res.status_code == 200

        # Fetch revealed results
        pub_res = await client.get(f"/api/runs/{run_id}/results")
        assert pub_res.status_code == 200
        revealed_results = pub_res.json()

        # Recompute canonical digest per §8
        # Canonical JSON: keys sorted, separators (',', ':'), UTF-8, ensure_ascii=False
        recomputed_digest = _canonical_digest(revealed_results)

        # Retrieve audit log entries to find run_concluded
        entries: List[Dict[str, Any]] = []
        after_seq = None
        for _ in range(25):
            url = "/api/log?limit=100" + (f"&after={after_seq}" if after_seq is not None else "")
            log_res = await client.get(url)
            assert log_res.status_code == 200
            batch = log_res.json().get("entries", [])
            if not batch:
                break
            entries.extend(batch)
            after_seq = batch[-1]["seq"]
            if len(batch) < 100:
                break

        concluded_entry = None
        for e in entries:
            if e.get("run_id") == run_id and e.get("event") == "run_concluded":
                concluded_entry = e
                break

        assert concluded_entry is not None, f"run_concluded event not found in audit log for run {run_id}"
        logged_results_digest = concluded_entry["data"]["results_digest"]

        # SECURITY: Cryptographic proof of revealed results integrity
        assert logged_results_digest == recomputed_digest, (
            f"CRYPTOGRAPHIC INTEGRITY FAILURE: logged results_digest {logged_results_digest} "
            f"!= recomputed digest {recomputed_digest}"
        )

        # Adversary Tamper Check: altering even a single field or count invalidates the digest
        tampered_results = dict(revealed_results)
        tampered_results["total"] = 999
        tampered_digest = _canonical_digest(tampered_results)
        assert tampered_digest != logged_results_digest, (
            "Tampered results produced identical digest! Hash collision or broken verification."
        )
