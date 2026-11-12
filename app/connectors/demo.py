from collections import defaultdict
from datetime import date

from .base import Hit


class DemoConnector:
    """Fake source to try the app without an API key.

    The first pass returns old leaks (the baseline); from the second pass on, a new leak appears so you can see an alert.
    """

    name = "Demo"

    def __init__(self) -> None:
        self._calls: dict[str, int] = defaultdict(int)

    def check_domain(self, domain: str) -> list[Hit]:
        self._calls[domain] += 1
        hits = [
            Hit(f"contact@{domain}", self.name, "Craftsmen directory (fictional)", date(2024, 3, 14), ("Email addresses", "Phone numbers")),
            Hit(f"rh@{domain}", self.name, "E-learning platform (fictional)", date(2023, 6, 2), ("Email addresses", "Password hashes")),
            Hit(f"s.petit@{domain}", self.name, "Contest forum (fictional)", date(2022, 1, 19), ("Email addresses", "Passwords")),
        ]
        if self._calls[domain] >= 2:
            hits.append(
                Hit(f"c.martin@{domain}", self.name, "Infostealer logs (fictional)", date(2026, 11, 9), ("Email addresses", "Session cookies"))
            )
        return hits
