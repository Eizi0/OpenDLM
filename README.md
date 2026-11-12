# OpenDLM

**Open Data Leak Monitor** : une application auto-hébergée qui surveille si les adresses e-mail de vos domaines apparaissent dans des fuites de données, vous prévient sur le canal de votre choix, et garde l'historique.

## Principes

- **Aucun contenu de fuite n'est conservé.** Seuls l'adresse concernée, le nom de la fuite, sa date, la source et les types de données exposées sont enregistrés. Jamais de mot de passe.
- **API officielles uniquement**, avec un User-Agent identifié. Pas de scraping d'interface web.
- **Propriété du domaine prouvée** (enregistrement TXT DNS) avant tout scan, pour qu'on ne puisse pas lister les adresses d'une autre organisation.
- **Base de référence silencieuse** : le premier passage d'une source enregistre les fuites déjà connues sans alerter. Seules les nouveautés déclenchent une notification.

## Démarrage rapide (Docker)

```bash
cp .env.example .env          # puis adapter les valeurs
OPENDLM_DEMO=true docker compose up -d --build
```

L'interface est disponible sur http://127.0.0.1:8080. En mode démo, un connecteur fictif simule une nouvelle fuite dès le deuxième scan.

Au premier lancement, ouvrez l'interface : une page vous demande de créer le compte administrateur (mot de passe d'au moins 12 caractères). Les mots de passe sont hachés avec scrypt, les sessions sont signées, et les tentatives de connexion répétées sont bloquées temporairement.

Par défaut l'application n'écoute que sur `127.0.0.1`. Pour l'ouvrir au réseau, placez-la derrière un proxy HTTPS (Traefik, Caddy, nginx) et activez `OPENDLM_COOKIE_SECURE=true`.

## Configuration

Variables d'environnement (voir `.env.example`) :

| Variable | Rôle |
|---|---|
| `POSTGRES_PASSWORD` | Mot de passe de la base PostgreSQL |
| `OPENDLM_DEMO` | `true` pour le connecteur fictif |
| `OPENDLM_HIBP_API_KEY` | Clé API Have I Been Pwned |
| `OPENDLM_NOTIFY_URLS` | URLs [Apprise](https://github.com/caronc/apprise), séparées par des virgules (Discord, ntfy, e-mail, Matrix…) |
| `OPENDLM_SCAN_HOUR` | Heure du scan quotidien (défaut 6) |
| `OPENDLM_TIMEZONE` | Fuseau horaire (défaut `Europe/Paris`) |
| `OPENDLM_COOKIE_SECURE` | `true` derrière un proxy HTTPS |

## Sources

- **Have I Been Pwned** : nécessite une clé payante et un domaine vérifié sur le tableau de bord HIBP. Les données sont sous licence [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) : la source doit rester citée là où elles sont affichées.

Chaque utilisateur est responsable du respect des conditions d'utilisation des sources qu'il active.

## Développement

```bash
docker run --rm -v "$PWD":/srv -w /srv python:3.12-slim \
  sh -c "pip install -q -r requirements-dev.txt && python -m pytest -q"
```
