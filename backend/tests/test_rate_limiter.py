"""
Tests for token bucket rate limiter.
"""

import asyncio
import time
import pytest
from backend.llm import TokenBucketRateLimiter


@pytest.mark.asyncio
async def test_token_bucket_initial_burst():
    # Rate limiter with 10 tokens per minute
    limiter = TokenBucketRateLimiter(requests_per_minute=10)

    # Initial token should be available with zero wait time
    wait1 = await limiter.acquire()
    assert wait1 == 0.0
    assert limiter.tokens < 10.0


@pytest.mark.asyncio
async def test_token_bucket_refill_and_wait():
    # 60 tokens per minute = 1 token per second
    limiter = TokenBucketRateLimiter(requests_per_minute=60)
    # Drain tokens
    limiter.tokens = 0.0
    limiter.last_update = time.monotonic()

    # Acquiring should wait ~1.0 second
    start = time.monotonic()
    wait = await limiter.acquire()
    elapsed = time.monotonic() - start
    assert wait > 0.0
    assert elapsed >= 0.8

