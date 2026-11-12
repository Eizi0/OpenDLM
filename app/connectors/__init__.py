from ..config import settings
from ..runtime_config import cfg
from .base import AddressConnector, Connector
from .demo import DemoConnector
from .hibp import HibpConnector
from .hudson_rock import HudsonRockConnector
from .leakcheck import LeakCheckConnector
from .xposedornot import XposedOrNotConnector

# Single instance: the demo connector remembers how many passes it made per domain.
_demo = DemoConnector()


def build_connectors() -> list[Connector]:
    """Domain-wide connectors that are active according to the configuration."""
    connectors: list[Connector] = []
    if settings.demo:
        connectors.append(_demo)
    if cfg.hibp_api_key:
        connectors.append(HibpConnector(cfg.hibp_api_key, settings.user_agent))
    if cfg.hudson_rock_key:
        connectors.append(HudsonRockConnector(cfg.hudson_rock_key, settings.user_agent))
    return connectors


def build_address_connectors() -> list[AddressConnector]:
    """Per-address connectors that were switched on in the interface (opt-in: they query third parties)."""
    connectors: list[AddressConnector] = []
    if cfg.leakcheck_enabled:
        connectors.append(LeakCheckConnector(settings.user_agent))
    if cfg.xposedornot_enabled:
        connectors.append(XposedOrNotConnector(settings.user_agent))
    return connectors


def active_source_names() -> list[str]:
    return [c.name for c in build_connectors()] + [c.name for c in build_address_connectors()]
