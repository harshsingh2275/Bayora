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

class CommitRequest(StrictBase):
    count: Annotated[int, Field(ge=1, le=100)]
    digests: list[Annotated[str, Field(min_length=64, max_length=64)]]
    set_digest: Annotated[str, Field(min_length=64, max_length=64)]


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

class RunResultAttackItem(BaseModel):
    """SECURITY §5: Prompt preview max 80 chars, outcome, latency; no full response, no rule_id."""
    idx: int
    prompt_digest: str
    prompt_preview: str
    outcome: str
    latency_ms: float | None = None


class RunResultsResponse(BaseModel):
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
    modes: dict[str, Any] = Field(default_factory=dict)
    verdict: dict[str, Any] | str = Field(default_factory=dict)
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
    modes: dict[str, Any] = Field(default_factory=dict)
    verdict: dict[str, Any] | str = Field(default_factory=dict)
    raw_samples: dict[str, Any] = Field(default_factory=dict)
    summary: dict[str, Any] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
