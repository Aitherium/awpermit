"""Spend ledgers: the memory a total cap needs.

A per-transaction cap is stateless. A total cap is not: "under the limit" is a
claim about every earlier spend on the same permit. `charge` is check-and-add in
one step, so two concurrent spends cannot both pass a check the pair exceeds.

`MemorySpend` is per-process. A platform running several workers needs a shared
implementation (one row per permit, an atomic UPDATE ... WHERE spent + n <= cap).
"""

from __future__ import annotations

import threading
import time
from typing import Optional, Protocol


class Spend(Protocol):
    def charge(self, key: str, amount: int, limit: int, expires_at: float) -> bool:
        """Add `amount` to `key`'s total if the result stays <= `limit`.

        Returns True when charged, False when it would exceed. Never charges on False.
        """
        ...


class MemorySpend:
    """In-process ledger. Forgets a permit's total once the permit has expired."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._spent: dict[str, tuple[int, float]] = {}

    def charge(self, key: str, amount: int, limit: int, expires_at: float,
               now: Optional[float] = None) -> bool:
        t = time.time() if now is None else now
        with self._lock:
            for k in [k for k, (_, exp) in self._spent.items() if exp < t]:
                del self._spent[k]
            spent, _ = self._spent.get(key, (0, expires_at))
            if spent + amount > limit:
                return False
            self._spent[key] = (spent + amount, expires_at)
            return True

    def spent(self, key: str) -> int:
        with self._lock:
            return self._spent.get(key, (0, 0.0))[0]
