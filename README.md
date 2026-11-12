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
| `OPENDLM_HUDSON_ROCK_KEY` | Clé API Hudson Rock (permission `search-by-domain`) |
| `OPENDLM_RANSOMWARE_LIVE_KEY` | Clé API PRO ransomware.live (gratuite) |
| `OPENDLM_NEWS_INTERVAL_MINUTES` | Fréquence de lecture des actus (défaut 30) |
| `OPENDLM_NEWS_RETENTION_DAYS` | Durée de conservation des actus (défaut 90) |
| `OPENDLM_ALLOW_PRIVATE_FEEDS` | `true` pour autoriser des flux sur le réseau interne |
| `OPENDLM_REPORT_DAILY` / `OPENDLM_REPORT_MONTHLY` | Active les rapports quotidien et mensuel (défaut `true`) |
| `OPENDLM_REPORT_HOUR` | Heure d'envoi des rapports (défaut 7) |
| `OPENDLM_REPORT_SEND_EMPTY` | Envoie aussi un rapport « rien à signaler » (signal de vie, défaut `true`) |
| `OPENDLM_ALERT_MIN_SEVERITY` | Seuil des alertes immédiates : `low`, `high` ou `critical` |
| `OPENDLM_SCAN_HOUR` | Heure du scan quotidien (défaut 6) |
| `OPENDLM_TIMEZONE` | Fuseau horaire (défaut `Europe/Paris`) |
| `OPENDLM_COOKIE_SECURE` | `true` derrière un proxy HTTPS |

## Alertes et rapports

- **Alerte immédiate** dès qu'une nouvelle fuite est détectée (adresse, fuite, source, date, types de données, jamais de mot de passe). Le seuil de gravité se règle avec `OPENDLM_ALERT_MIN_SEVERITY` ; ce qui est sous le seuil figure dans le rapport.
- **Rapport quotidien** (dernières 24 h) et **rapport mensuel** (mois civil précédent), envoyés sur vos canaux en Markdown, archivés dans l'application, et exportables en HTML ou Markdown. Un rapport « rien à signaler » est envoyé par défaut : son absence indique que le service ne tourne plus.

## Sources

- **Have I Been Pwned** : nécessite une clé payante et un domaine vérifié sur le tableau de bord HIBP. Les données sont sous licence [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) : la source doit rester citée là où elles sont affichées.

- **Hudson Rock (Cavalier v3)** : comptes de vos domaines dérobés par des logiciels espions (infostealers). Une clé dont le plan inclut la permission `search-by-domain` est nécessaire. Seules les 20 infections les plus récentes sont lues à chaque passage ; ni mot de passe, ni adresse IP, ni nom de machine ne sont conservés. Une fuite de ce type est classée « critique » : un simple changement de mot de passe ne suffit pas, les sessions ont pu être volées.
- **FrenchBreaches** (flux RSS public) : veille indépendante sur les fuites en France, avec un niveau de fiabilité par annonce. Seuls le titre, un extrait et le lien sont conservés, avec renvoi vers la source.
- **ransomware.live** (API PRO, clé gratuite) : revendications de groupes de rançongiciel. Ce sont des revendications, pas des faits établis.
- **Flux RSS/Atom de votre choix**, ajoutés depuis la page Sources (les adresses internes sont refusées). Le flux CERT-FR est fourni désactivé : il traite de vulnérabilités, pas de fuites.

Les actus qui contiennent l'un de vos mots surveillés (ou l'un de vos noms de domaine) déclenchent une alerte. Le premier passage d'une source ne fait qu'enregistrer l'historique, sans alerter.

Chaque utilisateur est responsable du respect des conditions d'utilisation des sources qu'il active.

## Développement

```bash
docker run --rm -v "$PWD":/srv -w /srv python:3.12-slim \
  sh -c "pip install -q -r requirements-dev.txt && python -m pytest -q"
```
