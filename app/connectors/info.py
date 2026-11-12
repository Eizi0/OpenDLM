"""Connector guide: what each source is, what it costs, how to get access, its limits and privacy impact.

Shown on the Sources page and mirrored in docs/connectors.md. All texts are translatable.
"""

from ..i18n import N_

# kind: domain (asks about a whole domain), address (asks about each monitored address), news (feeds)
INFO: dict[str, dict] = {
    "hibp": {
        "kind": "domain", "key": "hibp_api_key", "name": "Have I Been Pwned",
        "site": "https://haveibeenpwned.com", "signup": "https://haveibeenpwned.com/API/Key", "docs": "https://haveibeenpwned.com/API/v3",
        "cost": N_("Paid (plans start at about 4 USD per month)"),
        "desc": N_("The reference breach database. Lists every address of your domain found in known breaches, in one request."),
        "steps": [
            N_("Create an account on haveibeenpwned.com and open the dashboard."),
            N_("Buy a plan: Core is enough to monitor your own domains."),
            N_("Add your domain in the dashboard and verify it (DNS record or e-mail)."),
            N_("Copy the API key and paste it below, then click Test connection."),
        ],
        "limits": N_("Depends on the plan. One request per domain and scan."),
        "privacy": N_("Only the domain name is sent."),
        "credit": N_("Data is licensed CC BY 4.0: Have I Been Pwned must stay credited."),
    },
    "hudson_rock": {
        "kind": "domain", "key": "hudson_rock_key", "name": "Hudson Rock (Cavalier)",
        "site": "https://www.hudsonrock.com", "signup": "https://www.hudsonrock.com/free-api-key", "docs": "https://docs.hudsonrock.com",
        "cost": N_("Free key on request (reviewed by Hudson Rock, for development and testing); full access is commercial"),
        "desc": N_("Accounts of your domains stolen by infostealer malware. The most actionable signal: sessions may have been stolen too."),
        "steps": [
            N_("Fill in the request form on hudsonrock.com/free-api-key with a corporate e-mail address and your purpose."),
            N_("Wait for their team to review the request and send the key."),
            N_("Paste the key below and click Test connection: it checks the search-by-domain permission."),
            N_("If the permission is missing, ask Hudson Rock for the access level that includes it."),
        ],
        "limits": N_("50 requests per 10 seconds, 20 infections per response."),
        "privacy": N_("Only the domain name is sent. No password, IP address or machine name is stored."),
        "credit": None,
    },
    "leakcheck": {
        "kind": "address", "toggle": "leakcheck_enabled", "name": "LeakCheck",
        "site": "https://leakcheck.io", "signup": None, "docs": "https://docs.leakcheck.io/public-api/lookup",
        "cost": N_("Free, no key, commercial use allowed"),
        "desc": N_("Checks each monitored address and tells which breaches it appears in. Works address by address, not by domain."),
        "steps": [
            N_("Switch it on below."),
            N_("Open a domain and list the addresses to monitor (a shared mailbox, executives, key staff...)."),
            N_("OpenDLM checks them in small batches every hour and alerts on new findings."),
        ],
        "limits": N_("1 request per second. It names the breaches but cannot say which data each one exposed."),
        "privacy": N_("The address itself is never sent: only a truncated SHA-256 hash of it."),
        "credit": N_("Requires a \"Powered by LeakCheck\" link, shown in the sidebar while this source is on."),
    },
    "xposedornot": {
        "kind": "address", "toggle": "xposedornot_enabled", "name": "XposedOrNot",
        "site": "https://xposedornot.com", "signup": None, "docs": "https://xposedornot.com/api_doc",
        "cost": N_("Free, no key, for personal and low-volume use"),
        "desc": N_("Open-source breach checker. Gives the breach, its date and the kinds of data exposed (including passwords) for each address."),
        "steps": [
            N_("Read the privacy note, then switch it on below."),
            N_("Open a domain and list the addresses to monitor."),
            N_("OpenDLM checks about 90 addresses per day at most, to stay under the free limits."),
        ],
        "limits": N_("25 requests per hour and 100 per day per IP: with many addresses, each one is checked every few days."),
        "privacy": N_("The address is sent in clear to api.xposedornot.com (no hash lookup exists), so it is off by default."),
        "credit": None,
    },
    "ransomware_live": {
        "kind": "news", "key": "ransomware_live_key", "name": "ransomware.live (PRO API)",
        "site": "https://www.ransomware.live", "signup": "https://my.ransomware.live", "docs": "https://www.ransomware.live/api",
        "cost": N_("Free (the PRO API key costs nothing, business use allowed)"),
        "desc": N_("Ransomware group claims, used for the news feed and your watched words."),
        "steps": [
            N_("Create an account on my.ransomware.live."),
            N_("Generate your API key there."),
            N_("Paste it below and click Test connection."),
        ],
        "limits": N_("500,000 calls per month, fair use."),
        "privacy": N_("No data about you is sent."),
        "credit": None,
    },
}

ORDER = ["hibp", "hudson_rock", "leakcheck", "xposedornot", "ransomware_live"]
KEYED = {cid: i["key"] for cid, i in INFO.items() if "key" in i}
TOGGLED = {cid: i["toggle"] for cid, i in INFO.items() if "toggle" in i}
