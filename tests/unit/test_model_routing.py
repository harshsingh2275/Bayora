"""
tests/unit/test_model_routing.py
Unit tests for model client routing across tenant model instances (Architecture §9 fallback).

SECURITY invariants:
  SI-03 – model-red-net and model-blue-net are isolated internal networks.
  SI-04 – Gateway is the sole route to the models; tenants never contact models directly.
  SI-06 – Gateway builds model requests; cache_mode semantics determine tenant routing.
"""
import pytest
from gateway.app.model_client import get_model_url, _build_request_body
from gateway.app.config import MODEL_RED_URL, MODEL_BLUE_URL


def test_routing_isolated_mode():
    """In isolated mode, red routes to model-red and blue routes to model-blue."""
    assert get_model_url("red", "isolated") == MODEL_RED_URL
    assert get_model_url("blue", "isolated") == MODEL_BLUE_URL
    # Default without explicit role falls back to model-red
    assert get_model_url(None, "isolated") == MODEL_RED_URL


def test_routing_shared_mode():
    """In shared mode, both tenants are routed to the same model instance (model-red)."""
    assert get_model_url("red", "shared") == MODEL_RED_URL
    assert get_model_url("blue", "shared") == MODEL_RED_URL
    assert get_model_url(None, "shared") == MODEL_RED_URL


def test_build_request_body_isolated():
    """Isolated mode assigns slot 0 to red and slot 1 to blue with cache_prompt=True."""
    req_red = _build_request_body(prompt="hello red", max_tokens=32, role="red", cache_mode="isolated")
    assert req_red["id_slot"] == 0
    assert req_red["cache_prompt"] is True
    assert req_red["temperature"] == 0.0
    assert req_red["max_tokens"] == 32

    req_blue = _build_request_body(prompt="hello blue", max_tokens=32, role="blue", cache_mode="isolated")
    assert req_blue["id_slot"] == 1
    assert req_blue["cache_prompt"] is True


def test_build_request_body_shared():
    """Shared mode enables prompt cache without slot pinning."""
    req_red = _build_request_body(prompt="shared prompt", max_tokens=16, role="red", cache_mode="shared")
    assert "id_slot" not in req_red
    assert req_red["cache_prompt"] is True

    req_blue = _build_request_body(prompt="shared prompt", max_tokens=16, role="blue", cache_mode="shared")
    assert "id_slot" not in req_blue
    assert req_blue["cache_prompt"] is True
