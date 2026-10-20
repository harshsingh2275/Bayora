"""Tests for the custom seccomp profile (security/seccomp-tenant.json).

SECURITY: Verifies that tenant containers are protected by a strict seccomp
profile derived from Docker's default profile with additional denials for
ptrace, keyctl, personality changes, userfaultfd, and cross-process tracing.
Source: docs/architecture.md §3, §15 item 5; task X-01 / T10.
"""

from __future__ import annotations

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SECCOMP_PROFILE_PATH = REPO_ROOT / "security" / "seccomp-tenant.json"
COMPOSE_PATH = REPO_ROOT / "docker-compose.yml"


def test_seccomp_profile_file_exists_and_is_valid_json() -> None:
    """Verify that security/seccomp-tenant.json exists and parses as valid JSON."""
    assert SECCOMP_PROFILE_PATH.is_file(), f"Profile not found at {SECCOMP_PROFILE_PATH}"
    with open(SECCOMP_PROFILE_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert isinstance(data, dict), "Profile must be a JSON object"
    assert data.get("defaultAction") == "SCMP_ACT_ERRNO", "defaultAction must be SCMP_ACT_ERRNO"
    assert data.get("defaultErrnoRet") == 1, "defaultErrnoRet must be 1 (EPERM)"


def test_seccomp_profile_no_allow_rules_for_ptrace_or_process_vm() -> None:
    """Verify ptrace, process_vm_readv, process_vm_writev never appear in SCMP_ACT_ALLOW rules."""
    with open(SECCOMP_PROFILE_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    forbidden_allows = {"ptrace", "process_vm_readv", "process_vm_writev", "kcmp", "pidfd_getfd", "process_madvise"}
    for idx, rule in enumerate(data.get("syscalls", [])):
        action = rule.get("action")
        names = set(rule.get("names", []))
        if action == "SCMP_ACT_ALLOW":
            overlap = names & forbidden_allows
            assert not overlap, f"Rule {idx} improperly allows {overlap}"


def test_seccomp_profile_personality_changes_forbidden() -> None:
    """Verify personality changes (0, 8, 131072, 131080) are stripped from SCMP_ACT_ALLOW rules."""
    with open(SECCOMP_PROFILE_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    forbidden_values = {0, 8, 131072, 131080}
    for idx, rule in enumerate(data.get("syscalls", [])):
        if "personality" in rule.get("names", []):
            action = rule.get("action")
            args = rule.get("args", [])
            if action == "SCMP_ACT_ALLOW":
                for arg in args:
                    val = arg.get("value")
                    assert val not in forbidden_values, (
                        f"Rule {idx} allows forbidden personality change value {val}"
                    )


def test_seccomp_profile_explicit_errno_denies() -> None:
    """Verify explicit SCMP_ACT_ERRNO rule exists for ptrace, keyctl, userfaultfd and similar."""
    with open(SECCOMP_PROFILE_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    denied_syscalls: set[str] = set()
    for rule in data.get("syscalls", []):
        if rule.get("action") == "SCMP_ACT_ERRNO":
            denied_syscalls.update(rule.get("names", []))

    required_denies = {
        "ptrace",
        "keyctl",
        "userfaultfd",
        "process_vm_readv",
        "process_vm_writev",
        "kcmp",
        "pidfd_getfd",
        "process_madvise",
        "add_key",
        "request_key",
    }
    missing = required_denies - denied_syscalls
    assert not missing, f"Missing explicit SCMP_ACT_ERRNO rules for: {missing}"


def test_compose_applies_seccomp_tenant_profile() -> None:
    """Verify docker-compose.yml applies the profile to red, blue and gateway via security_opt."""
    compose_text = COMPOSE_PATH.read_text(encoding="utf-8")
    expected_entry = "seccomp:./security/seccomp-tenant.json"

    assert compose_text.count(expected_entry) >= 2, (
        f"Expected at least 2 occurrences of {expected_entry} in docker-compose.yml"
    )

    # Verify per-service blocks
    current_service = None
    service_opts: dict[str, list[str]] = {}
    for line in compose_text.splitlines():
        trimmed = line.strip()
        if line.startswith("  ") and not line.startswith("    ") and trimmed.endswith(":"):
            svc = trimmed[:-1]
            if not svc.startswith("#"):
                current_service = svc
                service_opts[current_service] = []
        elif current_service and trimmed.startswith("- ") and "seccomp" in trimmed:
            service_opts[current_service].append(trimmed.strip("- \"'"))

    for target in ["red", "blue", "gateway"]:
        assert any("seccomp-tenant.json" in opt for opt in service_opts.get(target, [])), (
            f"Service {target} missing seccomp-tenant.json in compose security_opt: {service_opts.get(target)}"
        )
