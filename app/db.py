from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy.pool import StaticPool

from .config import settings


class Base(DeclarativeBase):
    pass


if settings.database_url.startswith("sqlite"):
    # Tests : une seule connexion partagée, sinon chaque connexion verrait une base vide.
    engine = create_engine(settings.database_url, connect_args={"check_same_thread": False}, poolclass=StaticPool)
else:
    engine = create_engine(settings.database_url, pool_pre_ping=True)

SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
