from alembic import context
from sqlalchemy import create_engine, pool

from app import models  # noqa: F401  (enregistre les tables dans Base.metadata)
from app.config import settings
from app.db import Base

config = context.config
target_metadata = Base.metadata


def _url() -> str:
    return config.attributes.get("url") or settings.database_url


def run_migrations_online() -> None:
    engine = create_engine(_url(), poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=connection.dialect.name == "sqlite",
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


run_migrations_online()
