import hashlib
from datetime import date, datetime

import httpx

from .base import ConnectorError, Hit

API = "https://api.hudsonrock.com/json/v3"
DATA_CLASSES = ("Stealer logs", "Passwords", "Email addresses")


def _day(raw: str | None) -> date | None:
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).date()
    except ValueError:
        return None


class HudsonRockConnector:
    """Hudson Rock Cavalier (API v3) : comptes de vos domaines volés par des logiciels espions.

    Nécessite une clé dont le plan donne la permission « search-by-domain ».
    Seules les 20 infections les plus récentes sont lues (tri par date décroissante) : suffisant
    pour détecter les nouveautés à chaque passage. Ne conserve ni mot de passe, ni IP, ni nom de machine.
    """

    name = "Hudson Rock"

    def __init__(self, api_key: str, user_agent: str, client: httpx.Client | None = None) -> None:
        self._headers = {"api-key": api_key, "user-agent": user_agent, "accept": "application/json"}
        self._client = client or httpx.Client(timeout=100)  # la source peut mettre jusqu'à 90 s

    def check_domain(self, domain: str) -> list[Hit]:
        body = {"domains": [domain], "types": ["employees"], "sort_by": "date_compromised", "sort_direction": "desc"}
        try:
            r = self._client.post(f"{API}/search-by-domain", json=body, headers=self._headers)
        except httpx.HTTPError as e:
            raise ConnectorError(f"Hudson Rock injoignable : {e}") from e
        if r.status_code == 429:
            raise ConnectorError("Hudson Rock : limite de débit atteinte", retry_after=_retry_after(r))
        if r.status_code == 401:
            raise ConnectorError("Hudson Rock : clé API refusée")
        if r.status_code == 403:
            raise ConnectorError("Hudson Rock : permission « search-by-domain » absente de votre plan, ou domaine non autorisé")
        if r.status_code == 404:
            return []
        if r.status_code != 200:
            raise ConnectorError(f"Hudson Rock : réponse inattendue ({r.status_code})")
        try:
            data = r.json().get("data") or []
        except (ValueError, AttributeError) as e:
            raise ConnectorError("Hudson Rock : réponse illisible") from e
        return list(_hits(data, domain))


def _retry_after(r: httpx.Response) -> int:
    try:
        return int(r.headers.get("retry-after", "10"))
    except ValueError:
        return 10


def _hits(stealers: list, domain: str):
    suffix = "@" + domain
    for s in stealers:
        if not isinstance(s, dict):
            continue
        day = _day(s.get("date_compromised"))
        family = str(s.get("stealer_family") or "inconnu")[:40]
        # Identifiant de poste stable mais non réversible : distingue deux infections le même jour.
        machine = hashlib.sha256(f"{s.get('computer_name', '')}|{s.get('ip', '')}|{s.get('stealer', '')}".encode()).hexdigest()[:6]
        breach = f"Logs infostealer {family} · {day.strftime('%d/%m/%Y') if day else 'date inconnue'} · poste {machine}"
        for c in s.get("credentials") or []:
            if not isinstance(c, dict):
                continue
            user = str(c.get("username") or "").strip().lower()
            # Les identifiants masqués (••••) ne permettent pas d'identifier l'adresse : on le dit sans la deviner.
            identifier = user if user.endswith(suffix) and "•" not in user else f"[adresse masquée]{suffix}"
            yield Hit(identifier=identifier[:320], source=HudsonRockConnector.name, breach=breach, breach_date=day, data_classes=DATA_CLASSES)
