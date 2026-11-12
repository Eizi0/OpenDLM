from pathlib import Path

from alembic import command
from alembic.config import Config

ROOT = Path(__file__).resolve().parent.parent


def alembic_config(url: str | None = None) -> Config:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    if url:
        cfg.attributes["url"] = url
    return cfg


def upgrade(url: str | None = None) -> None:
    """Applique toutes les migrations en attente."""
    command.upgrade(alembic_config(url), "head")
