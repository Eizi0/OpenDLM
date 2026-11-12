from datetime import date

import httpx

from .base import ConnectorError, Hit

API = "https://haveibeenpwned.com/api/v3"


class HibpConnector:
    """Have I Been Pwned, API officielle uniquement.

    Nécessite une clé payante et un domaine vérifié sur le tableau de bord HIBP.
    Les données de HIBP sont sous licence CC BY 4.0 : la source doit rester citée.
    """

    name = "HIBP"

    def __init__(self, api_key: str, user_agent: str, client: httpx.Client | None = None) -> None:
        self._headers = {"hibp-api-key": api_key, "user-agent": user_agent}
        self._client = client or httpx.Client(timeout=20)
        self._catalog: dict[str, dict] | None = None

    def _get(self, path: str) -> httpx.Response:
        try:
            r = self._client.get(f"{API}{path}", headers=self._headers)
        except httpx.HTTPError as e:
            raise ConnectorError(f"HIBP injoignable : {e}") from e
        if r.status_code == 429:
            raise ConnectorError("HIBP : limite de débit atteinte", retry_after=int(r.headers.get("retry-after", "60")))
        if r.status_code == 401:
            raise ConnectorError("HIBP : clé API refusée")
        if r.status_code == 403:
            raise ConnectorError("HIBP : domaine non vérifié ou plan insuffisant")
        return r

    def _breach_catalog(self) -> dict[str, dict]:
        if self._catalog is None:
            r = self._get("/breaches")
            if r.status_code != 200:
                raise ConnectorError(f"HIBP : catalogue indisponible ({r.status_code})")
            self._catalog = {b["Name"]: b for b in r.json()}
        return self._catalog

    def check_domain(self, domain: str) -> list[Hit]:
        r = self._get(f"/breacheddomain/{domain}")
        if r.status_code == 404:
            return []
        if r.status_code != 200:
            raise ConnectorError(f"HIBP : réponse inattendue ({r.status_code})")
        catalog = self._breach_catalog()
        hits: list[Hit] = []
        for alias, breaches in r.json().items():
            for name in breaches:
                meta = catalog.get(name, {})
                raw_date = meta.get("BreachDate")
                hits.append(
                    Hit(
                        identifier=f"{alias}@{domain}",
                        source=self.name,
                        breach=meta.get("Title", name),
                        breach_date=date.fromisoformat(raw_date) if raw_date else None,
                        data_classes=tuple(meta.get("DataClasses", ())),
                    )
                )
        return hits
