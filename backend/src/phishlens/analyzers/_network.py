"""Shared plumbing for analyzers that call external reputation services.

Every lookup has a timeout, results (including "nothing found") are cached, and
failures become AnalyzerUnavailable so the verdict is still produced without them.
These services only ever receive a domain name, a URL, or a file hash: we never
visit a suspicious link or upload an attachment.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Hashable
from concurrent.futures import ThreadPoolExecutor, wait
from typing import Any

import httpx2

from phishlens.models import AnalyzerUnavailable

DEFAULT_TIMEOUT_SECONDS = 5.0
USER_AGENT = "PhishLens/0.1 (email security analysis)"

_MISSING = object()


class TTLCache:
    """Small thread-safe in-memory cache. Least recently used entries are evicted first."""

    def __init__(self, ttl_seconds: float, max_items: int = 4096, clock=time.monotonic) -> None:
        self.ttl, self.max_items, self._clock = ttl_seconds, max_items, clock
        self._items: OrderedDict[Hashable, tuple[float, Any]] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: Hashable, default: Any = _MISSING) -> Any:
        with self._lock:
            entry = self._items.get(key)
            if entry is None or entry[0] < self._clock():
                self._items.pop(key, None)
                return default
            self._items.move_to_end(key)
            return entry[1]

    def set(self, key: Hashable, value: Any) -> None:
        with self._lock:
            self._items[key] = (self._clock() + self.ttl, value)
            self._items.move_to_end(key)
            while len(self._items) > self.max_items:
                self._items.popitem(last=False)

    def cached[V](self, key: Hashable, compute: Callable[[], V]) -> V:
        """Return the cached value or compute and store it. Errors are not cached."""
        value = self.get(key)
        if value is _MISSING:
            value = compute()
            self.set(key, value)
        return value


def make_client(timeout: float = DEFAULT_TIMEOUT_SECONDS) -> httpx2.Client:
    return httpx2.Client(timeout=timeout, headers={"User-Agent": USER_AGENT}, follow_redirects=True)


def run_lookups[K: Hashable, V](
    keys: list[K], lookup: Callable[[K], V], deadline_seconds: float
) -> dict[K, V | Exception]:
    """Run lookups in parallel. Each key maps to its result, or to the exception it raised."""
    if not keys:
        return {}
    executor = ThreadPoolExecutor(max_workers=min(8, len(keys)))
    try:
        futures = {key: executor.submit(lookup, key) for key in keys}
        wait(futures.values(), timeout=deadline_seconds)
        results: dict[K, V | Exception] = {}
        for key, future in futures.items():
            if not future.done():
                results[key] = TimeoutError("lookup timed out")
            elif future.exception() is not None:
                results[key] = future.exception()  # type: ignore[assignment]
            else:
                results[key] = future.result()
        return results
    finally:
        executor.shutdown(wait=False, cancel_futures=True)


def unavailable(service: str, error: BaseException) -> AnalyzerUnavailable:
    """A user-facing reason for a failed lookup. Never includes URLs, which may carry API keys."""
    if isinstance(error, (httpx2.TimeoutException, TimeoutError)):
        return AnalyzerUnavailable(f"{service} timed out.")
    if isinstance(error, httpx2.HTTPStatusError):
        status = error.response.status_code
        if status in (401, 403):
            return AnalyzerUnavailable(f"{service} rejected the API key.")
        if status == 429:
            return AnalyzerUnavailable(f"{service} rate limit reached; try again shortly.")
        return AnalyzerUnavailable(f"{service} returned an error (HTTP {status}).")
    if isinstance(error, httpx2.HTTPError):
        return AnalyzerUnavailable(f"Couldn't reach {service}.")
    return AnalyzerUnavailable(f"{service} returned an unexpected response.")


def partial_results[K: Hashable, V](service: str, results: dict[K, V | Exception]) -> dict[K, V]:
    """Successful results only. Raises when every lookup failed, so the gap is reported."""
    ok = {k: v for k, v in results.items() if not isinstance(v, Exception)}
    if results and not ok:
        raise unavailable(service, next(iter(results.values())))  # type: ignore[arg-type]
    return ok
