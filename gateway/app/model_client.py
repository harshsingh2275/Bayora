"""
gateway/app/model_client.py
HTTP client for the llama.cpp model server.

SECURITY invariants:
  SI-06 – The gateway builds the model request itself.  Tenants never supply
           model parameters.  id_slot and cache_prompt are chosen by the
           gateway based on the current cache mode and the tenant's role.
  SI-08 – Only the 'content' field from the model response is returned.
           All other fields (timings, usage, tokens_cached, slot_id, etc.)
           are stripped before the response leaves this function.

Verified llama.cpp behavior (docs/verified-notes.md §3, §4):
  - /v1/chat/completions accepts id_slot and cache_prompt natively.
  - isolated mode: red → id_slot=0, blue → id_slot=1.
  - shared mode: no id_slot, cache_prompt omitted (server chooses by prefix similarity).
"""
import logging
from typing import Literal

import httpx

from .config import (
    ATTACK_MAX_TOKENS,
    MODEL_BLUE_URL,
    MODEL_RED_URL,
    MODEL_SYSTEM_PROMPT,
    MODEL_TEMPERATURE,
    MODEL_URL,
)

log = logging.getLogger("gateway.model_client")

# SECURITY SI-08: These are the ONLY fields we extract from the model response.
# Anything not in this set is silently dropped before reaching any caller.
_WHITELISTED_RESPONSE_FIELDS: frozenset[str] = frozenset({"text"})


def get_model_url(role: Literal["red", "blue"] | None, cache_mode: str) -> str:
    """
    Route model request to the appropriate model instance (Architecture §9 fallback):
    - In 'shared' mode: both tenants route to the same instance (model-red)
      so prefix KV-cache reuse occurs across tenants.
    - In 'isolated' mode: blue routes to model-blue (on model-blue-net),
      and red routes to model-red (on model-red-net), physically isolating KV cache.
    """
    if cache_mode == "shared":
        # Shared mode: both tenants routed to the same instance (model-red)
        return MODEL_RED_URL
    if role == "blue":
        return MODEL_BLUE_URL
    return MODEL_RED_URL


def _extract_text(raw: dict) -> str:
    """
    Extract the assistant's reply text from a /v1/chat/completions response.
    SECURITY SI-08: all other fields (timings, usage, slot_id, tokens_cached,
    prompt_tokens, cache fields) are discarded here.
    """
    try:
        return raw["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        log.error({"event": "model_response_parse_error"})
        return ""


def _build_request_body(
    *,
    prompt: str,
    max_tokens: int,
    role: Literal["red", "blue"] | None,
    cache_mode: str,
) -> dict:
    """
    Build the model request dict.
    SECURITY SI-06: This is the ONLY place that constructs the model request.
    - System prompt, temperature, and max_tokens are fixed by config.
    - Slot parameters are determined by the gateway based on role + cache_mode.
    - No tenant-supplied parameters are forwarded.

    Verified field names (docs/verified-notes.md §3, §4):
      id_slot (int)      – pins generation to a specific KV cache slot
      cache_prompt (bool) – enables/disables KV cache reuse for the prompt
    """
    body: dict = {
        "messages": [
            {"role": "system", "content": MODEL_SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "temperature": MODEL_TEMPERATURE,      # SECURITY SI-06: always 0
        "max_tokens": max_tokens,              # SECURITY SI-06: capped by caller
        # stream=False is the default but stated explicitly
        "stream": False,
    }

    # Prompt caching is active; physical tenant instance routing enforces isolation in isolated mode
    body["cache_prompt"] = True
    if cache_mode == "isolated" and role is not None:
        slot = 0 if role == "red" else 1
        body["id_slot"] = slot          # verified field name
        log.debug({"event": "model_request_slot", "role": role, "slot": slot, "mode": "isolated"})
    else:
        log.debug({"event": "model_request_slot", "role": role, "mode": "shared"})

    return body


async def call_model(
    *,
    prompt: str,
    max_tokens: int,
    role: Literal["red", "blue"] | None = None,
    cache_mode: str = "isolated",
    timeout: float = 60.0,
) -> str:
    """
    Send a chat-completion request to the model server and return ONLY the
    assistant text.

    SECURITY SI-04 / §9 fallback: Routes by tenant to model-red or model-blue.
    SECURITY SI-06: builds the request itself; never forwards client params.
    SECURITY SI-08: strips all non-whitelisted fields from the response.
    """
    body = _build_request_body(
        prompt=prompt,
        max_tokens=max_tokens,
        role=role,
        cache_mode=cache_mode,
    )
    target_url = get_model_url(role, cache_mode)

    async with httpx.AsyncClient(base_url=target_url, timeout=timeout) as client:
        resp = await client.post("/v1/chat/completions", json=body)
        resp.raise_for_status()
        raw: dict = resp.json()

    # SECURITY SI-08: extract only the text; discard everything else
    text = _extract_text(raw)
    return text


async def erase_slot(slot_id: int, timeout: float = 5.0) -> None:
    """
    Erase the KV cache for a slot across both model instances after run conclusion.
    Verified endpoint: POST /slots/{id_slot}?action=erase (docs/verified-notes.md §5).
    No-op if the server returns non-200 (best-effort; not fail-closed).
    """
    for base_url in (MODEL_RED_URL, MODEL_BLUE_URL):
        try:
            async with httpx.AsyncClient(base_url=base_url, timeout=timeout) as client:
                resp = await client.post(f"/slots/{slot_id}?action=erase")
                if resp.status_code == 200:
                    log.info({"event": "slot_erased", "slot_id": slot_id, "url": base_url})
                else:
                    log.warning({"event": "slot_erase_failed", "slot_id": slot_id,
                                 "url": base_url, "status": resp.status_code})
        except Exception as exc:
            log.warning({"event": "slot_erase_error", "slot_id": slot_id, "url": base_url, "error": str(exc)})
