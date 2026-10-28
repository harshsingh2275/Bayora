"""
gateway/app/taxonomies.py
Shared taxonomy allowlists for attack sources and categories.

SECURITY:
- Only allowlisted sources and categories may be committed by the red team.
- No free text from the red team reaches public results endpoints.
- Used by gateway pydantic models and scripts/prepare_datasets.py.
"""
from typing import Literal

ALLOWED_SOURCES = (
    "advbench",
    "gandalf",
    "advbench+roleplay",
    "advbench+ignore_instructions",
    "advbench+academic_research",
    "advbench+system_override",
    "advbench+hypothetical",
    "gandalf+roleplay",
    "gandalf+system_override",
    "custom",
)

ALLOWED_CATEGORIES = (
    "harmful_behavior",
    "prompt_injection",
    "roleplay_jailbreak",
    "academic_framing",
    "hypothetical_framing",
    "test",
)

AttackSource = Literal[
    "advbench",
    "gandalf",
    "advbench+roleplay",
    "advbench+ignore_instructions",
    "advbench+academic_research",
    "advbench+system_override",
    "advbench+hypothetical",
    "gandalf+roleplay",
    "gandalf+system_override",
    "custom",
]

AttackCategory = Literal[
    "harmful_behavior",
    "prompt_injection",
    "roleplay_jailbreak",
    "academic_framing",
    "hypothetical_framing",
    "test",
]
