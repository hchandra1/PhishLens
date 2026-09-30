"""In-memory sliding-window rate limiting per client.

Enough for a single-instance deployment. Several instances behind a load balancer
would need a shared store (e.g. Redis) instead.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque


class RateLimiter:
    def __init__(
        self, limit: int, window_seconds: float, max_clients: int = 10_000, clock=time.monotonic
    ) -> None:
        self.limit, self.window, self.max_clients, self._clock = (
            limit,
            window_seconds,
            max_clients,
            clock,
        )
        self._hits: OrderedDict[str, deque[float]] = OrderedDict()
        self._lock = threading.Lock()

    def check(self, client: str) -> float | None:
        """Record a request. Returns None if allowed, else seconds until the client may retry."""
        now = self._clock()
        with self._lock:
            hits = self._hits.pop(client, None) or deque()
            while hits and hits[0] <= now - self.window:
                hits.popleft()
            self._hits[client] = hits  # most recently seen clients last
            if len(self._hits) > self.max_clients:
                self._hits.popitem(last=False)
            if len(hits) >= self.limit:
                return max(0.0, hits[0] + self.window - now)
            hits.append(now)
            return None


def parse_rate(spec: str) -> tuple[int, float]:
    """'30/minute' -> (30, 60.0). Also accepts second, hour."""
    count, _, unit = spec.partition("/")
    seconds = {"second": 1.0, "minute": 60.0, "hour": 3600.0}[unit.strip().rstrip("s") or "minute"]
    return int(count), seconds
