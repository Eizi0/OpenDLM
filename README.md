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
12 characters). Then add your keys on the Sources page. In demo mode a fake connector simulates a new leak from the second scan on (the news feed is real).

By default the app only listens on `127.0.0.1`. To open it to a network, put it behind an HTTPS reverse proxy
(Traefik, Caddy, nginx) and set `OPENDLM_COOKIE_SECURE=true`.

## Configuration

Everything is configured **in the web interface**, by an administrator:

| Page | What you set |
|---|---|
| **Sources** | API key per connector (Have I Been Pwned, Hudson Rock, ransomware.live), with a *Test connection* button; RSS/Atom news feeds |
| **Notifications** | Notification channels (any [Apprise](https://github.com/caronc/apprise) URL: Discord, ntfy, e-mail, Matrix...), with a per-channel test |
| **Settings** | Default language, timezone, scan and report schedule, alert threshold, news polling and retention |
| **Users** | Accounts and roles (administrator or read-only viewer) |

Changes apply immediately, without restarting. API keys and channel URLs are **encrypted in the database**; the master key
lives in the `/data` volume (or in `OPENDLM_SECRET_KEY`), never in the database. Back it up: without it, saved secrets cannot
be decrypted.

Every setting can also be given as an environment variable (see `.env.example`); a value saved in the interface takes
precedence, and *Reset* on a settings section falls back to the environment.

Each user can pick their own interface language (English or French) from the sidebar or their profile.

## Sources

Full guide, with costs, how to get access, limits and privacy impact: **[docs/connectors.md](docs/connectors.md)** (the same guide is built into the Sources page, with links to each provider).

| Source | Works | Cost |
|---|---|---|
| [Have I Been Pwned](https://haveibeenpwned.com) | per domain | paid API key, domain verified |
| [Hudson Rock, official API](https://www.hudsonrock.com/free-api-key) | per domain (accounts stolen by infostealers, with the addresses) | free key on request, full access commercial |
| [Hudson Rock, free tools](https://www.hudsonrock.com/free-tools) | domain count + per monitored address (unofficial, on by default, replaced by the official key) | free, no key |
| [LeakCheck](https://leakcheck.io) | per monitored address, **hashed** | free, no key |
| [XposedOrNot](https://xposedornot.com) | per monitored address, sent in clear (opt-in) | free, no key, low volume |
| [ransomware.live](https://www.ransomware.live) | news: ransomware claims | free PRO key |
| [FrenchBreaches](https://frenchbreaches.com) + any RSS/Atom feed | news | free |

The free per-address sources only need a list of addresses to watch on each domain page; they are checked in small batches every
hour within each provider's limits. LeakCheck requires a "Powered by LeakCheck" link, shown in the sidebar while it is on.
News that contains one of your watched words (or one of your domain names) triggers an alert. Each user is responsible for
complying with the terms of use of the sources they enable.

## Alerts and reports

- **Immediate alert** as soon as a new leak is found (address, breach, source, date, kinds of data; never a password).
  The severity threshold is set in Settings; anything below it appears in the report.
- **Daily report** (last 24 hours) and **monthly report** (previous calendar month), sent to your channels as Markdown,
  archived in the app, and exportable as HTML or Markdown. An "all clear" report is sent by default: its absence tells
  you the service stopped running.

## Day-to-day operation

- **Dashboard**: one bar per day over 60 days and per domain (green: fine, red: new leak, amber: partial scan). A banner
  warns when no scan ran for more than 26 hours while verified domains exist.
- **Finding statuses**: new, acknowledged, resolved (reopenable). Findings from the baseline stay "known".
- **Notifications page**: manage channels (tokens are never displayed again) and send a test message.
- **Two-factor authentication** (TOTP): each user can enable it from their profile, with a QR code, single-use recovery codes, protection against code replay, and an administrator reset for someone locked out.
- **Roles**: administrators change everything; viewers are read-only and cannot open Sources, Notifications, Settings or Users.

## API, exports and monitoring

Administrators create **read-only API tokens** on the *API access* page (a token is shown once; only its hash is stored).

```bash
curl -H "Authorization: Bearer odlm_..." https://your-host/api/v1/status
curl -H "Authorization: Bearer odlm_..." "https://your-host/api/v1/findings?status=new&severity=critical&format=csv"
curl -H "Authorization: Bearer odlm_..." "https://your-host/api/v1/news?mentions=1&format=json"
```

- `GET /api/v1/findings` (filters: `domain`, `status`, `severity`, `since`, `limit`) and `GET /api/v1/news` (`source`, `mentions`, `since`, `limit`), as JSON or CSV. CSV cells that could be read as spreadsheet formulas are neutralised.
- `GET /metrics` exposes Prometheus metrics (domains, findings by status and severity, last scan time, scanner stalled flag, failed queries, news source health).
- Signed-in users can download the same exports from the Domain and News pages.

Prometheus scrape example:

```yaml
scrape_configs:
  - job_name: opendlm
    authorization: { credentials: odlm_... }
    static_configs: [{ targets: ["your-host:8080"] }]
```

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
