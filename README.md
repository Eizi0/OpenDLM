# OpenDLM

**Open Data Leak Monitor** is a self-hosted service that watches whether the e-mail addresses of your domains show up in data
leaks, tells you on the channel of your choice, keeps the history, and sends a daily or monthly report. Think of it as an
uptime monitor, but for leaks.

It also aggregates leak announcements (FrenchBreaches, ransomware.live, any RSS/Atom feed) and warns you when one of
your watched names appears in them.

## Principles

- **No leaked content is ever stored.** Only the affected address, the breach name, its date, the source and the kinds of
  data exposed are kept. Never a password.
- **Official APIs and public feeds only**, with an identified User-Agent. No scraping of web interfaces.
- **Domain ownership is proven** (DNS TXT record) before any scan, so nobody can list another organisation's addresses.
- **Silent baseline**: the first pass of a source records what is already known without alerting. Only new findings notify you.

## Quick start (Docker)

```bash
cp .env.example .env            # then adjust the values
OPENDLM_DEMO=true docker compose up -d --build
```

Open http://127.0.0.1:8080. On first run a page asks you to create the administrator account (password of at least
12 characters). In demo mode a fake connector simulates a new leak from the second scan on (the news feed is real).

By default the app only listens on `127.0.0.1`. To open it to a network, put it behind an HTTPS reverse proxy
(Traefik, Caddy, nginx) and set `OPENDLM_COOKIE_SECURE=true`.

## Configuration

Settings are read from environment variables (see `.env.example`):

| Variable | Purpose |
|---|---|
| `POSTGRES_PASSWORD` | PostgreSQL password |
| `OPENDLM_DEMO` | `true` enables the fake demo connector |
| `OPENDLM_HIBP_API_KEY` | Have I Been Pwned API key |
| `OPENDLM_HUDSON_ROCK_KEY` | Hudson Rock API key (needs the `search-by-domain` permission) |
| `OPENDLM_RANSOMWARE_LIVE_KEY` | ransomware.live PRO API key (free) |
| `OPENDLM_NOTIFY_URLS` | Comma-separated [Apprise](https://github.com/caronc/apprise) URLs (Discord, ntfy, e-mail, Matrix…) |
| `OPENDLM_NEWS_INTERVAL_MINUTES` / `OPENDLM_NEWS_RETENTION_DAYS` | News polling interval (default 30) and retention (default 90 days) |
| `OPENDLM_ALLOW_PRIVATE_FEEDS` | `true` allows feeds hosted on your internal network |
| `OPENDLM_REPORT_DAILY` / `OPENDLM_REPORT_MONTHLY` | Enable the daily and monthly reports (default `true`) |
| `OPENDLM_REPORT_HOUR` | Hour the reports are sent (default 7) |
| `OPENDLM_REPORT_SEND_EMPTY` | Also send an "all clear" report (a heartbeat, default `true`) |
| `OPENDLM_ALERT_MIN_SEVERITY` | Immediate alert threshold: `low`, `high` or `critical` |
| `OPENDLM_SCAN_HOUR` | Hour of the daily scan (default 6) |
| `OPENDLM_TIMEZONE` | Timezone (default `Europe/Paris`) |
| `OPENDLM_COOKIE_SECURE` | `true` behind an HTTPS proxy |

## Sources

- **Have I Been Pwned**: needs a paid API key and a domain verified on the HIBP dashboard. Data is licensed
  [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/): the source must stay credited wherever it is displayed.
- **Hudson Rock (Cavalier v3)**: accounts of your domains stolen by infostealer malware. Needs a key whose plan includes the
  `search-by-domain` permission. Only the 20 most recent infections are read on each pass; no password, IP address or machine
  name is kept. Such a finding is rated *critical*: changing the password is not enough, sessions may have been stolen.
- **FrenchBreaches** (public RSS feed): independent monitoring of leaks in France, with a reliability level per announcement.
  Only the title, an excerpt and the link are stored, with a link back to the source.
- **ransomware.live** (PRO API, free key): ransomware group claims. These are claims, not established facts.
- **Any RSS/Atom feed**, added from the Sources page (internal addresses are refused). The CERT-FR feed ships disabled:
  it covers vulnerabilities, not leaks.

News that contains one of your watched words (or one of your domain names) triggers an alert. Each user is responsible for
complying with the terms of use of the sources they enable.

## Alerts and reports

- **Immediate alert** as soon as a new leak is found (address, breach, source, date, kinds of data; never a password).
  The severity threshold is set with `OPENDLM_ALERT_MIN_SEVERITY`; anything below it appears in the report.
- **Daily report** (last 24 hours) and **monthly report** (previous calendar month), sent to your channels as Markdown,
  archived in the app, and exportable as HTML or Markdown. An "all clear" report is sent by default: its absence tells
  you the service stopped running.

## Day-to-day operation

- **Dashboard**: one bar per day over 60 days and per domain (green: fine, red: new leak, amber: partial scan). A banner
  warns when no scan ran for more than 26 hours while verified domains exist.
- **Finding statuses**: new, acknowledged, resolved (reopenable). Findings from the baseline stay "known".
- **Notifications page**: lists the channels (tokens are never displayed) and sends a test message.

## Development

```bash
docker run --rm -v "$PWD":/srv -w /srv python:3.12-slim \
  sh -c "pip install -q -r requirements-dev.txt && python -m pytest -q"
```

Database migrations live in `migrations/` (Alembic) and run at startup.

## Third-party data

Breach data from Have I Been Pwned is licensed CC BY 4.0. FrenchBreaches and ransomware.live content remains theirs; OpenDLM
only keeps titles, short excerpts and links back to them.

## License

[MIT](LICENSE)
