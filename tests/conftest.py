import os

# Avant tout import de l'application : base de test locale, pas de PostgreSQL ni de planificateur.
os.environ["OPENDLM_DATABASE_URL"] = "sqlite://"
os.environ["OPENDLM_SCHEDULER_ENABLED"] = "false"

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.db import engine as app_engine


@pytest.fixture
def session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine, expire_on_commit=False)() as s:
        yield s


@pytest.fixture
def client():
    """Application complète sur une base vierge (migrations appliquées au démarrage)."""
    from app import main, security

    Base.metadata.drop_all(app_engine)
    with app_engine.begin() as conn:
        conn.execute(text("DROP TABLE IF EXISTS alembic_version"))
    security.reset_secret_cache()
    main.throttle = security.LoginThrottle()
    with TestClient(main.app, follow_redirects=False) as c:
        yield c


STRONG = "un-mot-de-passe-solide-123"


@pytest.fixture
def logged_client(client):
    r = client.post("/setup", data={"username": "admin", "password": STRONG, "confirm": STRONG})
    assert r.status_code == 303
    return client
