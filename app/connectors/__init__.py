from ..config import settings
from ..runtime_config import cfg
from .base import Connector
from .demo import DemoConnector
from .hibp import HibpConnector
from .hudson_rock import HudsonRockConnector

# Single instance: the demo connector remembers how many passes it made per domain.
_demo = DemoConnector()


def build_connectors() -> list[Connector]:
    """Active connectors according to the configuration."""
    connectors: list[Connector] = []
    if settings.demo:
        connectors.append(_demo)
    if cfg.hibp_api_key:
        connectors.append(HibpConnector(cfg.hibp_api_key, settings.user_agent))
    if cfg.hudson_rock_key:
        connectors.append(HudsonRockConnector(cfg.hudson_rock_key, settings.user_agent))
    return connectors
