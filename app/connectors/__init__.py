from ..config import settings
from .base import Connector
from .demo import DemoConnector
from .hibp import HibpConnector
from .hudson_rock import HudsonRockConnector

# Instance unique : le connecteur de démo garde en mémoire le nombre de passages par domaine.
_demo = DemoConnector()


def build_connectors() -> list[Connector]:
    """Connecteurs actifs selon la configuration."""
    connectors: list[Connector] = []
    if settings.demo:
        connectors.append(_demo)
    if settings.hibp_api_key:
        connectors.append(HibpConnector(settings.hibp_api_key, settings.user_agent))
    if settings.hudson_rock_key:
        connectors.append(HudsonRockConnector(settings.hudson_rock_key, settings.user_agent))
    return connectors
