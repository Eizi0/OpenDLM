from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect

from app import migrate
from app.db import Base


def test_migrations_match_models(tmp_path):
    """Si un modèle change sans migration, ce test échoue."""
    url = f"sqlite:///{tmp_path / 'm.db'}"
    migrate.upgrade(url)
    engine = create_engine(url)
    with engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn, opts={"compare_type": True}), Base.metadata)
    assert diff == [], f"modèles et migrations divergent : {diff}"
    assert "alembic_version" in inspect(engine).get_table_names()


def test_upgrade_is_idempotent(tmp_path):
    url = f"sqlite:///{tmp_path / 'm.db'}"
    migrate.upgrade(url)
    migrate.upgrade(url)
