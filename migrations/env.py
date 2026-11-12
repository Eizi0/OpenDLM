from alembic import context
from sqlalchemy import create_engine, pool

from app import models  # noqa: F401  (enregistre les tables dans Base.metadata)
from app.db import Base
from app.db import engine as app_engine

config = context.config
target_metadata = Base.metadata


def run_migrations_online() -> None:
    url = config.attributes.get("url")
    # Sans URL explicite : moteur de l'application (indispensable pour la base SQLite en mémoire des tests).
    engine = create_engine(url, poolclass=pool.NullPool) if url else app_engine
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
