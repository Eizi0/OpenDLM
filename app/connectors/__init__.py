from ..config import settings
from ..runtime_config import cfg
from .base import AddressConnector, Connector
from .demo import DemoConnector
from .hibp import HibpConnector
from .hudson_rock import HudsonRockConnector
from .hudson_rock_free import HudsonRockFreeAddress, HudsonRockFreeDomain
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
    elif cfg.hudson_rock_free_enabled:  # the official key replaces the free tools: no duplicate alerts
        connectors.append(HudsonRockFreeDomain(settings.user_agent))
    return connectors


def build_address_connectors() -> list[AddressConnector]:
    """Per-address connectors that were switched on in the interface (opt-in: they query third parties)."""
    connectors: list[AddressConnector] = []
    if cfg.hudson_rock_free_enabled and not cfg.hudson_rock_key:
        connectors.append(HudsonRockFreeAddress(settings.user_agent))
    if cfg.leakcheck_enabled:
        connectors.append(LeakCheckConnector(settings.user_agent))
    if cfg.xposedornot_enabled:
        connectors.append(XposedOrNotConnector(settings.user_agent))
    return connectors


def active_source_names() -> list[str]:
    names = [c.name for c in build_connectors()] + [c.name for c in build_address_connectors()]
    return list(dict.fromkeys(names))  # a source with a domain part and an address part is listed once
