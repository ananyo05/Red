"""
Tests for LLM disk caching mechanism.
"""

import shutil
from pathlib import Path
from backend.llm import DiskCache


def test_cache_miss_and_hit(tmp_path: Path):
    cache = DiskCache(tmp_path)
    model = "llama-3.1-8b-instant"
    messages = [{"role": "user", "content": "Hello RedLoop"}]
    temp = 0.0

    # 1. Miss initially
    miss = cache.get(model, messages, temp)
    assert miss is None

    # 2. Store response
    data = {
        "content": "Hello! I am ready.",
        "tool_calls": [],
        "latency_ms": 120.0,
        "cached": False,
        "model": model,
    }
    cache.set(model, messages, temp, data)

    # 3. Hit
    hit = cache.get(model, messages, temp)
    assert hit is not None
    assert hit["content"] == "Hello! I am ready."


def test_cache_key_sensitivity(tmp_path: Path):
    cache = DiskCache(tmp_path)
    model = "llama-3.1-8b-instant"
    messages1 = [{"role": "user", "content": "Prompt A"}]
    messages2 = [{"role": "user", "content": "Prompt B"}]

    cache.set(model, messages1, 0.0, {"content": "Response A"})

    # Should miss for different prompt
    assert cache.get(model, messages2, 0.0) is None
    # Should miss for different temperature
    assert cache.get(model, messages1, 0.7) is None
    # Should hit for exact match
    assert cache.get(model, messages1, 0.0)["content"] == "Response A"

