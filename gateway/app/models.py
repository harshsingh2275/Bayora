"""
gateway/app/models.py
Pydantic v2 request/response models for all gateway endpoints.

SECURITY invariants enforced at the schema layer:
  SI-06 – extra="forbid" on every request model: unknown fields (including
           tenant-supplied id_slot, cache_prompt, model params) are rejected 422.
  SI-08 – Response models expose only the whitelisted fields.
"""
from typing import Annotated, Any, Literal

import regex
from pydantic import BaseModel, ConfigDict, Field, model_validator


from .taxonomies import AttackCategory, AttackSource


# ── Shared base: SECURITY SI-06 – every request forbids extra fields ─────────
class StrictBase(BaseModel):
    model_config = ConfigDict(extra="forbid")



# ── Probe endpoint (/v1/red/probe, /v1/blue/probe) ────────────────────────────

class ProbeRequest(StrictBase):
    """SECURITY SI-06: extra="forbid" rejects id_slot, cache_prompt, etc."""
    prompt: Annotated[str, Field(max_length=16_000)]
    max_tokens: Annotated[int, Field(ge=1, le=128)]  # architecture §5: 1..128 for probes


class ProbeResponse(BaseModel):
    """SECURITY SI-08: only 'text' is returned to tenants."""
    text: str


# ── Work endpoint (/v1/{role}/work) ──────────────────────────────────────────

class RunParams(BaseModel):
    """Parameters embedded in a work response.  Fields depend on role."""
    attack_count: int | None = None
    seed: int | None = None
    bundle: str | None = None


class WorkResponse(BaseModel):
    run: dict[str, Any] | None = None


# ── Commit endpoint (/v1/red/runs/{run_id}/commit) ───────────────────────────

class CommitAttackItem(StrictBase):
    idx: Annotated[int, Field(ge=0, le=99)]
    source: AttackSource
    category: AttackCategory


class CommitRequest(StrictBase):
    count: Annotated[int, Field(ge=1, le=100)]
    digests: list[Annotated[str, Field(min_length=64, max_length=64)]]
    set_digest: Annotated[str, Field(min_length=64, max_length=64)]
    attacks: list[CommitAttackItem] | None = None

    @model_validator(mode="after")
    def validate_attacks(self) -> "CommitRequest":
        if len(self.digests) != self.count:
            raise ValueError(f"digests count {len(self.digests)} does not match count {self.count}")
        if self.attacks is not None:
            if len(self.attacks) != self.count:
                raise ValueError(f"attacks count {len(self.attacks)} does not match count {self.count}")
            for expected_idx, atk in enumerate(self.attacks):
                if atk.idx != expected_idx:
                    raise ValueError(f"attacks[{expected_idx}].idx is {atk.idx}, expected {expected_idx}")
        return self


class CommitResponse(BaseModel):
    ok: bool = True


# ── Defense endpoint (/v1/blue/runs/{run_id}/defense) ────────────────────────

class BundleRule(StrictBase):
    id: Annotated[str, Field(max_length=32)]
    type: Literal["contains", "regex"]
    pattern: Annotated[str, Field(max_length=200)]
    action: Literal["block"]

    @model_validator(mode="after")
    def validate_pattern(self) -> "BundleRule":
        # SECURITY SI-09: Validate regex syntax during upload; never execute
        if self.type == "regex":
            try:
                regex.compile(self.pattern)
            except Exception as e:
                raise ValueError(f"Invalid regex pattern: {e}") from e
        return self


class DefenseBundle(StrictBase):
    """SECURITY SI-09: Bundle is data, validated here, never executed."""
    version: Literal["baseline-v1", "hardened-v1"]
    input_rules: Annotated[list[BundleRule], Field(max_length=200)]
    output_rules: Annotated[list[BundleRule], Field(max_length=200)]
    refusal_text: Annotated[str, Field(max_length=200)]

    @model_validator(mode="after")
    def validate_total_rules(self) -> "DefenseBundle":
        # Architecture §7: At most 200 rules total across input and output
        if len(self.input_rules) + len(self.output_rules) > 200:
            raise ValueError("Total rules across input and output cannot exceed 200")
        return self


class DefenseRequest(StrictBase):
    bundle: DefenseBundle


class DefenseResponse(BaseModel):
    bundle_digest: str


# ── Attack endpoint (/v1/red/runs/{run_id}/attack) ───────────────────────────

class AttackRequest(StrictBase):
    idx: Annotated[int, Field(ge=0)]
    prompt: Annotated[str, Field(max_length=4_000)]


class AttackResponse(BaseModel):
    """SECURITY SI-08: only text and blocked flag exposed to tenants."""
    text: str
    blocked: bool


# ── Done endpoint (/v1/red/runs/{run_id}/done) ───────────────────────────────

class DoneRequest(StrictBase):
    sent: Annotated[int, Field(ge=0)]


class DoneResponse(BaseModel):
    ok: bool = True


# ── Reports (/v1/red/runs/{run_id}/report, /v1/blue/runs/{run_id}/report) ────

class RedAttackReport(BaseModel):
    """SECURITY §5 asymmetry: Red gets per-attack outcome only (no rule ids, no responses)."""
    idx: int
    outcome: str


class RedReportResponse(BaseModel):
    run_id: str
    state: str
    total: int
    asr: float
    attacks: list[RedAttackReport]


class BlueAttackReport(BaseModel):
    """SECURITY §5 asymmetry: Blue gets full details (prompt, outcome, rule_id, response)."""
    idx: int
    prompt: str
    outcome: str
    rule_id: str | None = None
    response_text: str
    latency_ms: float | None = None


class BlueReportResponse(BaseModel):
    run_id: str
    state: str
    total: int
    asr: float
    attacks: list[BlueAttackReport]


# ── Results (/api/runs/{run_id}/results) ──────────────────────────────────────

REDACTED_PROMPT_PREVIEW = "[PROMPT REDACTED FOR PUBLIC VIEW]"


class RunResultAttackItem(StrictBase):
    """
    SECURITY SI-08: idx, prompt_digest, source, category, outcome, latency_ms, prompt_preview.
    Harmful dataset text (e.g. AdvBench) is strictly masked to '[PROMPT REDACTED FOR PUBLIC VIEW]'.
    Raw prompt text ('prompt') and internal defense rule IDs ('rule_id') remain strictly forbidden.
    """
    idx: int
    prompt_digest: str
    source: AttackSource
    category: AttackCategory
    outcome: str
    latency_ms: float | None = None
    prompt_preview: str = REDACTED_PROMPT_PREVIEW

    @model_validator(mode="before")
    @classmethod
    def sanitize_preview(cls, data: Any) -> Any:
        if isinstance(data, dict):
            src = data.get("source") or ""
            cat = data.get("category") or ""
            # SECURITY SI-08: Fail-closed redaction.
            # Null / unknown source or category is treated as harmful and redacted.
            # This prevents null-source records (stored before the source column
            # existed) from leaking raw prompt text.
            _SAFE_SOURCES: frozenset[str] = frozenset()  # no public sources currently
            _HARMFUL_SOURCES: frozenset[str] = frozenset({
                "advbench",
                "advbench+roleplay",
                "advbench+ignore_instructions",
                "advbench+academic_research",
                "advbench+system_override",
                "advbench+hypothetical",
            })
            is_harmful = (
                not src                        # null / empty source → unknown → redact
                or src not in _SAFE_SOURCES    # not explicitly safe → redact
                or src in _HARMFUL_SOURCES     # explicitly harmful → redact
                or not cat                     # null / empty category → unknown → redact
                or cat == "harmful_behavior"   # explicitly harmful category → redact
            )
            if is_harmful or not data.get("prompt_preview"):
                data["prompt_preview"] = REDACTED_PROMPT_PREVIEW
            # SECURITY: Backfill source/category to safe defaults when null so that
            # Pydantic required-field validation doesn't 500 on legacy rows written
            # before these columns existed. Unknown source/category is always treated
            # as the most-harmful class (advbench / harmful_behavior).
            if not data.get("source"):
                data["source"] = "advbench"
            if not data.get("category"):
                data["category"] = "harmful_behavior"
        return data


class RunResultsResponse(StrictBase):
    run_id: str
    total: int
    aggregate: dict[str, int]
    asr: float
    attacks: list[RunResultAttackItem]


# ── Admin item detail (/api/admin/runs/{run_id}/items/{idx}) ──────────────────

class OperatorRunItemResponse(BaseModel):
    run_id: str
    idx: int
    prompt: str
    response_text: str
    outcome: str
    rule_id: str | None = None
    latency_ms: float | None = None


# ── Admin: create run (/api/runs POST) ────────────────────────────────────────

class CreateRunRequest(StrictBase):
    name: Annotated[str, Field(max_length=128)]
    attack_count: Annotated[int, Field(ge=1, le=100)]
    seed: int
    bundle: Literal["baseline", "hardened"]


class CreateRunResponse(BaseModel):
    run_id: str
    state: str


class AbortRunResponse(BaseModel):
    run_id: str
    state: str


class RunDetailResponse(BaseModel):
    run_id: str
    name: str
    state: str
    attack_count: int
    seed: int
    bundle_name: str
    created_at: str
    updated_at: str
    red_committed: bool = False
    blue_committed: bool = False
    set_digest: str | None = None
    bundle_digest: str | None = None


# ── Admin: cache mode (/api/admin/cache-mode POST) ───────────────────────────

class CacheModeRequest(StrictBase):
    mode: Literal["isolated", "shared"]


class CacheModeResponse(BaseModel):
    mode: str


# ── Health ─────────────────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str
    service: str = "gateway"


class AggregatedHealthResponse(BaseModel):
    status: str
    services: dict[str, str]


# ── Run list (/api/runs GET) ──────────────────────────────────────────────────

class RunListItem(BaseModel):
    run_id: str
    name: str
    state: str
    attack_count: int
    seed: int
    bundle_name: str
    created_at: str
    updated_at: str
    red_committed: bool = False
    blue_committed: bool = False
    set_digest: str | None = None
    bundle_digest: str | None = None


class RunListResponse(BaseModel):
    runs: list[RunListItem]


# ── Topology (/api/topology GET) ──────────────────────────────────────────────

class TopologyService(BaseModel):
    name: str
    image: str
    networks: list[str]
    purpose: str
    tcb: bool
    isolated: bool


class TopologyNetwork(BaseModel):
    name: str
    internal: bool
    description: str
    services: list[str]


class TopologyResponse(BaseModel):
    services: list[TopologyService]
    networks: list[TopologyNetwork]
    invariants: list[str]


# ── Break-it reports (/api/breakit/*) ─────────────────────────────────────────

class BreakitProbe(StrictBase):
    id: str = Field(..., max_length=16)
    category: str = Field(..., max_length=32)
    description: str = Field(..., max_length=256)
    expected: str = Field(..., max_length=256)
    observed: str = Field(..., max_length=256)
    passed: bool


class BreakitSummary(StrictBase):
    total: int = Field(default=0, ge=0)
    passed: int = Field(default=0, ge=0)
    failed: int = Field(default=0, ge=0)


class BreakitReportRequest(StrictBase):
    generated_at: str = ""
    git_commit: str = ""
    probes: list[BreakitProbe] = Field(default_factory=list)
    summary: BreakitSummary = Field(default_factory=BreakitSummary)


class BreakitReportIngestResponse(BaseModel):
    status: str = "ok"
    summary: BreakitSummary


class BreakitReportResponse(BaseModel):
    generated_at: str
    git_commit: str
    probes: list[BreakitProbe]
    summary: BreakitSummary


# ── Timing experiment reports (/api/experiments/timing/*) ─────────────────────

class TimingReportRequest(StrictBase):
    generated_at: str = ""
    git_commit: str = ""
    environment: dict[str, Any] = Field(default_factory=dict)
    protocol: dict[str, Any] = Field(default_factory=dict)
    modes: dict[str, Any] = Field(default_factory=dict)
    verdict: dict[str, Any] | str = Field(default_factory=dict)
    verdict_rule: str = ""
    raw_samples: dict[str, Any] = Field(default_factory=dict)
    summary: dict[str, Any] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)


class TimingReportIngestResponse(BaseModel):
    status: str = "ok"
    verdict: dict[str, Any] | str = Field(default_factory=dict)


class TimingReportResponse(BaseModel):
    generated_at: str = ""
    git_commit: str = ""
    environment: dict[str, Any] = Field(default_factory=dict)
    protocol: dict[str, Any] = Field(default_factory=dict)
    modes: dict[str, Any] = Field(default_factory=dict)
    verdict: dict[str, Any] | str = Field(default_factory=dict)
    verdict_rule: str = ""
    raw_samples: dict[str, Any] = Field(default_factory=dict)
    summary: dict[str, Any] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
