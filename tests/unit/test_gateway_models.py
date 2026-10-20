"""
tests/unit/test_gateway_models.py
Unit tests for Pydantic request models — verifying extra="forbid" enforcement.

SECURITY SI-06: every test that sends a forbidden field must get a ValidationError.
AGENTS.md §5: security tests try to violate the property and assert the attempt fails.
"""
import pytest
from pydantic import ValidationError

from gateway.app.models import (
    AttackRequest,
    CommitRequest,
    DefenseBundle,
    DefenseRequest,
    DoneRequest,
    ProbeRequest,
    BundleRule,
    CacheModeRequest,
    CreateRunRequest,
)


# ── ProbeRequest ──────────────────────────────────────────────────────────────

class TestProbeRequest:
    def test_valid_probe(self):
        req = ProbeRequest(prompt="hello", max_tokens=10)
        assert req.prompt == "hello"
        assert req.max_tokens == 10

    def test_max_tokens_min_boundary(self):
        ProbeRequest(prompt="x", max_tokens=1)  # should not raise

    def test_max_tokens_max_boundary(self):
        ProbeRequest(prompt="x", max_tokens=128)  # should not raise

    def test_max_tokens_zero_rejected(self):
        """max_tokens < 1 must be rejected (architecture §5: 1..128)."""
        with pytest.raises(ValidationError):
            ProbeRequest(prompt="x", max_tokens=0)

    def test_max_tokens_over_cap_rejected(self):
        """SECURITY A7: max_tokens > 128 must yield 422."""
        with pytest.raises(ValidationError):
            ProbeRequest(prompt="x", max_tokens=129)

    def test_id_slot_rejected(self):
        """SECURITY SI-06: id_slot is a forbidden field — tenant cannot pin slots."""
        with pytest.raises(ValidationError) as exc_info:
            ProbeRequest(prompt="x", max_tokens=10, id_slot=0)
        assert "id_slot" in str(exc_info.value)

    def test_cache_prompt_rejected(self):
        """SECURITY SI-06: cache_prompt is a forbidden field."""
        with pytest.raises(ValidationError) as exc_info:
            ProbeRequest(prompt="x", max_tokens=10, cache_prompt=True)
        assert "cache_prompt" in str(exc_info.value)

    def test_unknown_field_rejected(self):
        """SECURITY SI-06: any unknown field must be rejected."""
        with pytest.raises(ValidationError):
            ProbeRequest(prompt="x", max_tokens=10, evil_param="inject")

    def test_temperature_rejected(self):
        """SECURITY SI-06: tenant cannot override temperature."""
        with pytest.raises(ValidationError):
            ProbeRequest(prompt="x", max_tokens=10, temperature=1.0)

    def test_model_rejected(self):
        """SECURITY SI-06: tenant cannot choose a different model."""
        with pytest.raises(ValidationError):
            ProbeRequest(prompt="x", max_tokens=10, model="gpt-4")

    def test_prompt_length_limit(self):
        """max_length=16000 for probe prompts."""
        long_prompt = "a" * 16_001
        with pytest.raises(ValidationError):
            ProbeRequest(prompt=long_prompt, max_tokens=10)

    def test_prompt_at_limit_accepted(self):
        ProbeRequest(prompt="a" * 16_000, max_tokens=10)


# ── CommitRequest ─────────────────────────────────────────────────────────────

class TestCommitRequest:
    def _valid_digest(self) -> str:
        return "a" * 64

    def test_valid_commit(self):
        req = CommitRequest(
            count=3,
            digests=[self._valid_digest() for _ in range(3)],
            set_digest=self._valid_digest(),
        )
        assert req.count == 3

    def test_unknown_field_rejected(self):
        with pytest.raises(ValidationError):
            CommitRequest(
                count=1,
                digests=[self._valid_digest()],
                set_digest=self._valid_digest(),
                extra="evil",
            )

    def test_count_zero_rejected(self):
        with pytest.raises(ValidationError):
            CommitRequest(count=0, digests=[], set_digest=self._valid_digest())

    def test_digest_wrong_length_rejected(self):
        with pytest.raises(ValidationError):
            CommitRequest(count=1, digests=["abc"], set_digest=self._valid_digest())


# ── AttackRequest ─────────────────────────────────────────────────────────────

class TestAttackRequest:
    def test_valid_attack(self):
        req = AttackRequest(idx=0, prompt="do something harmful")
        assert req.idx == 0

    def test_unknown_field_rejected(self):
        with pytest.raises(ValidationError):
            AttackRequest(idx=0, prompt="x", id_slot=1)

    def test_prompt_too_long_rejected(self):
        with pytest.raises(ValidationError):
            AttackRequest(idx=0, prompt="a" * 4_001)


# ── DefenseBundle / BundleRule ─────────────────────────────────────────────────

class TestDefenseBundle:
    def _valid_rule(self, rule_id="I1", rtype="contains", pattern="ignore"):
        return {"id": rule_id, "type": rtype, "pattern": pattern, "action": "block"}

    def test_valid_bundle(self):
        DefenseBundle(
            version="hardened-v1",
            input_rules=[self._valid_rule()],
            output_rules=[],
            refusal_text="Blocked.",
        )

    def test_valid_bundle_baseline(self):
        DefenseBundle(
            version="baseline-v1",
            input_rules=[self._valid_rule()],
            output_rules=[],
            refusal_text="Blocked.",
        )

    def test_actual_bundle_files(self):
        import json
        from pathlib import Path
        repo_root = Path(__file__).resolve().parent.parent.parent
        for name in ("baseline.json", "hardened.json"):
            path = repo_root / "data" / "blue" / "bundles" / name
            assert path.is_file(), f"Bundle file missing: {path}"
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            bundle = DefenseBundle.model_validate(data)
            assert bundle.refusal_text

    def test_invalid_version_rejected(self):
        with pytest.raises(ValidationError):
            DefenseBundle(
                version="evil-v99",
                input_rules=[],
                output_rules=[],
                refusal_text="x",
            )

    def test_unknown_rule_field_rejected(self):
        """SECURITY SI-09: unknown fields in rules must be rejected."""
        with pytest.raises(ValidationError):
            rule = self._valid_rule()
            rule["exec"] = "os.system('rm -rf /')"
            DefenseBundle(
                version="hardened-v1",
                input_rules=[rule],
                output_rules=[],
                refusal_text="x",
            )

    def test_invalid_action_rejected(self):
        with pytest.raises(ValidationError):
            rule = self._valid_rule()
            rule["action"] = "allow"
            DefenseBundle(
                version="hardened-v1",
                input_rules=[rule],
                output_rules=[],
                refusal_text="x",
            )

    def test_too_many_rules_rejected(self):
        rules = [self._valid_rule(rule_id=f"I{i}") for i in range(201)]
        with pytest.raises(ValidationError):
            DefenseBundle(
                version="hardened-v1",
                input_rules=rules,
                output_rules=[],
                refusal_text="x",
            )

    def test_pattern_too_long_rejected(self):
        with pytest.raises(ValidationError):
            BundleRule(id="I1", type="contains", pattern="a" * 201, action="block")

    def test_refusal_text_too_long_rejected(self):
        with pytest.raises(ValidationError):
            DefenseBundle(
                version="hardened-v1",
                input_rules=[],
                output_rules=[],
                refusal_text="x" * 201,
            )


# ── CacheModeRequest ──────────────────────────────────────────────────────────

class TestCacheModeRequest:
    def test_isolated_valid(self):
        CacheModeRequest(mode="isolated")

    def test_shared_valid(self):
        CacheModeRequest(mode="shared")

    def test_invalid_mode_rejected(self):
        with pytest.raises(ValidationError):
            CacheModeRequest(mode="unsafe")

    def test_unknown_field_rejected(self):
        with pytest.raises(ValidationError):
            CacheModeRequest(mode="isolated", extra="field")


# ── CreateRunRequest ──────────────────────────────────────────────────────────

class TestCreateRunRequest:
    def test_valid_run_request(self):
        CreateRunRequest(name="test-run", attack_count=5, seed=42, bundle="baseline")

    def test_attack_count_zero_rejected(self):
        with pytest.raises(ValidationError):
            CreateRunRequest(name="r", attack_count=0, seed=1, bundle="baseline")

    def test_attack_count_over_100_rejected(self):
        with pytest.raises(ValidationError):
            CreateRunRequest(name="r", attack_count=101, seed=1, bundle="baseline")

    def test_invalid_bundle_rejected(self):
        with pytest.raises(ValidationError):
            CreateRunRequest(name="r", attack_count=5, seed=1, bundle="evil-bundle")

    def test_unknown_field_rejected(self):
        with pytest.raises(ValidationError):
            CreateRunRequest(name="r", attack_count=5, seed=1, bundle="baseline", model="gpt-4")
