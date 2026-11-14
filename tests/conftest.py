import os
import tempfile

# Avant tout import de l'application : base de test locale, pas de PostgreSQL ni de planificateur.
# OPENDLM_TEST_DATABASE_URL runs the suite against PostgreSQL (CI); SQLite in memory otherwise.
os.environ["OPENDLM_DATABASE_URL"] = os.environ.get("OPENDLM_TEST_DATABASE_URL", "sqlite://")
os.environ["OPENDLM_SCHEDULER_ENABLED"] = "false"
os.environ["OPENDLM_REQUIRE_2FA"] = "off"  # existing tests sign in without a second factor
os.environ["OPENDLM_HUDSON_ROCK_FREE_ENABLED"] = "false"  # no network source unless a test turns it on
os.environ["OPENDLM_DATA_DIR"] = tempfile.mkdtemp(prefix="opendlm-test-")

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
    from app.web import auth
    from app.runtime_config import cfg

    Base.metadata.drop_all(app_engine)
    with app_engine.begin() as conn:
        conn.execute(text("DROP TABLE IF EXISTS alembic_version"))
    cfg._overrides.clear()
    cfg.invalidate()
    auth.throttle = security.LoginThrottle()
    with TestClient(main.app, follow_redirects=False) as c:
        yield c


STRONG = "un-mot-de-passe-solide-123"


@pytest.fixture
def logged_client(client):
    r = client.post("/setup", data={"username": "admin", "password": STRONG, "confirm": STRONG})
    assert r.status_code == 303
    return client


@pytest.fixture
def cfg_override():
    """Temporarily override runtime settings: cfg_override(hibp_api_key="x")."""
    from app.runtime_config import cfg

    def apply(**values):
        cfg._overrides.update(values)

    yield apply
    cfg._overrides.clear()
