from collections import defaultdict
from datetime import date

from .base import Hit


class DemoConnector:
    """Source fictive pour tester sans clé API.

    Le premier passage renvoie des fuites anciennes (la base de référence).
    Dès le deuxième passage, une nouvelle fuite apparaît, ce qui permet de voir une alerte.
    """

    name = "Démo"

    def __init__(self) -> None:
        self._calls: dict[str, int] = defaultdict(int)

    def check_domain(self, domain: str) -> list[Hit]:
        self._calls[domain] += 1
        hits = [
            Hit(f"contact@{domain}", self.name, "Annuaire des artisans (fictif)", date(2024, 3, 14), ("Email addresses", "Phone numbers")),
            Hit(f"rh@{domain}", self.name, "Plateforme e-learning (fictif)", date(2023, 6, 2), ("Email addresses", "Password hashes")),
            Hit(f"s.petit@{domain}", self.name, "Forum de jeux concours (fictif)", date(2022, 1, 19), ("Email addresses", "Passwords")),
        ]
        if self._calls[domain] >= 2:
            hits.append(
                Hit(f"c.martin@{domain}", self.name, "Logs infostealer (fictif)", date(2026, 11, 9), ("Email addresses", "Session cookies"))
            )
        return hits
