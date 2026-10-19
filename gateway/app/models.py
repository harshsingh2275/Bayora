"""
gateway/app/models.py
Pydantic v2 request/response models for all gateway endpoints.

SECURITY invariants enforced at the schema layer:
  SI-06 – extra="forbid" on every request model: unknown fields (including
           tenant-supplied id_slot, cache_prompt, model params) are rejected 422.
  SI-08 – Response models expose only the whitelisted fields.
"""
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

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


class DefenseBundle(StrictBase):
    """SECURITY SI-09: Bundle is data, validated here, never executed."""
    version: Literal["hardened-v1"]
    input_rules: Annotated[list[BundleRule], Field(max_length=200)]
    output_rules: Annotated[list[BundleRule], Field(max_length=200)]
    refusal_text: Annotated[str, Field(max_length=200)]


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


# ── Admin: create run (/api/runs POST) ────────────────────────────────────────

class CreateRunRequest(StrictBase):
    name: Annotated[str, Field(max_length=128)]
    attack_count: Annotated[int, Field(ge=1, le=100)]
    seed: int
    bundle: Literal["baseline", "hardened"]


class CreateRunResponse(BaseModel):
    run_id: str
    state: str


# ── Admin: cache mode (/api/admin/cache-mode POST) ───────────────────────────

class CacheModeRequest(StrictBase):
    mode: Literal["isolated", "shared"]


class CacheModeResponse(BaseModel):
    mode: str


# ── Health ─────────────────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str
    service: str = "gateway"
