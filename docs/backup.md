# Backup and restore

An OpenDLM instance is two things, and a backup needs **both**:

| What | Where | Why it matters |
|---|---|---|
| The PostgreSQL database | `pgdata` volume | Domains, findings, history, users, settings, encrypted secrets |
| The master key | `/data/secret.key` in the `appdata` volume, or `OPENDLM_SECRET_KEY` | Decrypts the API keys, notification URLs and two-factor secrets stored in the database |

Without the master key, a restored database still works, but every saved secret is unreadable: API keys and
channels have to be entered again, and users with two-factor authentication need a reset
(`python -m app.cli reset-2fa <user>`). Keep the key somewhere other than the database dump.

The commands below are run from the directory that holds `compose.yaml`.

## Back up

```bash
# Database (custom format, compressed)
docker compose exec -T db pg_dump -U opendlm -d opendlm -Fc > opendlm-$(date +%F).dump

# Master key (skip if you set OPENDLM_SECRET_KEY: back up that value instead)
docker compose exec -T app cat /data/secret.key > secret.key
chmod 600 secret.key
```

The dump holds e-mail addresses of your organisation and encrypted secrets: store it like any other
sensitive backup. Run it from cron, for example every night after the scan:

```cron
30 8 * * * cd /opt/opendlm && docker compose exec -T db pg_dump -U opendlm -d opendlm -Fc > backups/opendlm-$(date +\%F).dump
```

## Restore

On a new host, or after `docker compose down -v`:

```bash
# 1. Start the database alone, and load the dump
docker compose up -d db
docker compose exec -T db pg_restore -U opendlm -d opendlm --clean --if-exists --no-owner < opendlm-2026-11-14.dump

# 2. Put the master key back BEFORE the application starts
#    (on first start without a key, OpenDLM creates a new one, and the saved secrets become unreadable)
docker compose run --rm --no-deps -T app sh -c 'umask 077 && cat > /data/secret.key' < secret.key

# 3. Start the application (database migrations, if any, run on start)
docker compose up -d
```

Then sign in as usual: users, two-factor authentication, API keys and channels come back as they were.

This procedure was tested end to end: backup of a running instance, restore into an empty one, sign-in,
leaks and an encrypted notification URL read back correctly.

## Moving to a newer version

Back up first, then `git pull` (or pull the new image) and `docker compose up -d --build`. Database
migrations apply automatically on start. To roll back, restore the backup taken before the upgrade
with the previous version.
