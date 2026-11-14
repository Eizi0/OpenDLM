# Contributing to OpenDLM

Thanks for your interest. Bug reports, new sources, translations and test feedback from real deployments
are all welcome.

## Ground rules

- **No leaked content, ever.** A connector returns metadata only: which address, which breach, when, which kinds
  of data. Never a password, a hash, a cookie or a raw record, not even in logs or tests.
- **Sources must be legitimate.** Documented API, published terms that allow the use, identifiable operator, and no
  resale of stolen data. A service that sells access to breach dumps will not be merged, however useful.
- **Blue team only.** OpenDLM tells an organisation about its own exposure. Features that help look up someone
  else's addresses are out of scope (this is why domains must be verified by DNS before any scan).
- Security issues go through [private vulnerability reporting](SECURITY.md), not public issues.

## Development setup

You need Docker. Everything else runs in containers.

```bash
git clone https://github.com/Eizi0/OpenDLM.git && cd OpenDLM
cp .env.example .env
OPENDLM_DEMO=true docker compose up -d --build   # http://127.0.0.1:8080, fictional leaks
```

Run the tests (SQLite in memory, about a minute):

```bash
docker run --rm -v "$PWD":/src -w /src python:3.12-slim \
  sh -c "pip install -q -r requirements-dev.txt && python -m pytest -q"
```

The CI also runs them against PostgreSQL. To do the same locally, start a PostgreSQL container and set
`OPENDLM_TEST_DATABASE_URL=postgresql+psycopg://user:pass@host:5432/db`.

**Check your change in the running application, not only in tests.** Several real bugs in this project were
only visible there (a scheduler refusing to reconfigure, a demo connector recreated at every scan, a login
limit counting the reverse proxy instead of the visitor).

## Project layout

| Path | What |
|---|---|
| `app/connectors/` | Leak sources. `base.py` defines the two interfaces; `info.py` holds the guide shown on the Sources page |
| `app/scanner.py` | Silent baseline, new-finding detection, severity |
| `app/news.py`, `app/feeds.py` | Leak news, with SSRF and XML hardening |
| `app/web/` | One router per page |
| `app/locale/fr.py` | French translations (English message ids) |
| `migrations/versions/` | Alembic migrations, applied on start |

## Adding a leak source

1. **Pick the interface.** `Connector.check_domain(domain)` if the source answers for a whole domain;
   `AddressConnector.check_address(address)` if it only answers address by address (set `min_interval`,
   `batch_size` and `daily_budget` to stay within its free tier).
2. **Write `app/connectors/<name>.py`.** Return `Hit` objects. Raise `ConnectorError` (with `retry_after` when the
   source says so) on refusal, rate limit or outage: the scanner records it as a failed run and moves on. Use the
   configured User-Agent and a timeout. Look at `leakcheck.py` (address, keyless) or `hibp.py` (domain, API key).
3. **Register it** in `app/connectors/__init__.py`. A source that sends addresses to a third party must be
   off by default and switched on explicitly in the interface.
4. **If it needs a key**, add a `secret` setting in `app/runtime_config.py`: it is then stored encrypted and editable
   on the Sources page.
5. **Describe it** in `app/connectors/info.py` and `docs/connectors.md`: cost, how to get access, limits, and what it
   learns about you (privacy impact).
6. **Test it** with recorded or hand-written responses (`tests/test_address_sources.py` and `tests/test_hibp.py` show the pattern),
   and once against the real service if it has a free tier. Say in the pull request what you tested for real.

## Translations

Interface texts are English message ids wrapped in `_()` (templates) or `t()` / `N_()` (Python). Every id must
have a French entry in `app/locale/fr.py`; `tests/test_i18n.py` fails otherwise. Adding a language means a new
catalog next to `fr.py` and an entry in `app/i18n.py`.

## Database changes

Change `app/models.py`, then add a migration in `migrations/versions/` (next number, `down_revision` set to the
previous one). `tests/test_migrations.py` checks that migrations and models match.

## Pull requests

- One logical change per commit, with a message that says why.
- Tests pass, and new behaviour has a test.
- Documentation updated when the behaviour visible to users changes (README, `docs/`).
- Keep pull requests small; open an issue first for anything large.
