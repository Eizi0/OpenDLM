# Connector guide

OpenDLM gets its data from independent **sources**. Each one is configured on the **Sources** page, where the same guide is
shown next to a *Guide* disclosure, with links to the provider's website, the page to get access, and its documentation.

| Source | Works | Cost | Needs |
|---|---|---|---|
| [Have I Been Pwned](#have-i-been-pwned) | per domain | paid | API key + verified domain |
| [Hudson Rock](#hudson-rock-cavalier) | per domain | free key on request, full access commercial | API key with `search-by-domain` |
| [LeakCheck](#leakcheck) | per address | free | nothing (switch on) |
| [XposedOrNot](#xposedornot) | per address | free | nothing (switch on) |
| [ransomware.live](#ransomwarelive) | news | free | free PRO API key |
| [FrenchBreaches](#frenchbreaches-and-other-feeds) | news | free | nothing |

**Per domain** sources return every affected address of a domain in one request. **Per address** sources can only be asked
about one address at a time, so you list the addresses to watch on each domain page; OpenDLM checks them in small batches
every hour, stalest first, and respects each provider's limits.

In every case the first time a source checks something, what it already knows is recorded silently (the *baseline*). Only
later discoveries alert you.

## Have I Been Pwned

- Website: https://haveibeenpwned.com — get a key: https://haveibeenpwned.com/API/Key — docs: https://haveibeenpwned.com/API/v3
- **Cost:** paid; the *Core* plan (about 4 USD per month) covers your own domains.
- **Get access:** create an account, buy a plan, add your domain on the dashboard and verify it (DNS record or e-mail), copy the API key into OpenDLM and click *Test connection*.
- **Limits:** depend on the plan. One request per domain and scan.
- **Privacy:** only the domain name is sent.
- **Attribution:** the data is licensed CC BY 4.0; Have I Been Pwned must stay credited (reports include the credit).

## Hudson Rock (Cavalier)

- Website: https://www.hudsonrock.com — request a key: https://www.hudsonrock.com/free-api-key — docs: https://docs.hudsonrock.com
- **Cost:** a free key is available on request for development and testing (the team reviews each request; a corporate e-mail address is required). Full access is commercial.
- **Get access:** fill in the form with your purpose, wait for the key, paste it into OpenDLM and click *Test connection*: it checks the `search-by-domain` permission and tells you if it is missing.
- **Limits:** 50 requests per 10 seconds, 20 infections per response (the 20 most recent are read on each pass).
- **Privacy:** only the domain name is sent. No password, IP address or machine name is stored.
- A finding from this source is rated *critical*: changing the password is not enough, sessions may have been stolen.

## LeakCheck

- Website: https://leakcheck.io — docs: https://docs.leakcheck.io/public-api/lookup
- **Cost:** free, no key, commercial use allowed.
- **Get access:** switch it on in Sources, then list the addresses to monitor on each domain page.
- **Limits:** 1 request per second. It names the breaches (with month and year) but cannot say which data each one exposed, so its findings are rated *low* by default.
- **Privacy:** the address itself is never sent; OpenDLM sends a truncated SHA-256 hash of it (the format the API accepts).
- **Attribution:** LeakCheck requires a *"Powered by LeakCheck"* link; OpenDLM shows it in the sidebar while the source is on.

## XposedOrNot

- Website: https://xposedornot.com — docs: https://xposedornot.com/api_doc
- **Cost:** free, no key, "for personal and low-volume use" (paid plans exist for production workloads).
- **Get access:** read the privacy note, switch it on in Sources, list the addresses to monitor.
- **Limits:** 2 requests per second, 25 per hour and 100 per day per IP for e-mail checks. OpenDLM checks at most about 90 addresses per day; with many addresses, each one is checked every few days.
- **Privacy:** the address is sent in clear to `api.xposedornot.com` (there is no hash lookup), so the source is **off by default**. Decide whether this is acceptable for your addresses.
- It gives the breach, its date and the kinds of data exposed (including passwords), so findings are rated accurately.

## ransomware.live

- Website: https://www.ransomware.live — get a key: https://my.ransomware.live — docs: https://www.ransomware.live/api
- **Cost:** free; the PRO API key costs nothing and business use is allowed.
- **Get access:** create an account, generate the key, paste it into OpenDLM and click *Test connection*.
- **Limits:** 500,000 calls per month, fair use.
- **Privacy:** no data about you is sent. Entries are claims by ransomware groups, not established facts.

## FrenchBreaches and other feeds

FrenchBreaches (https://frenchbreaches.com) is a public RSS feed of leaks affecting French organisations, enabled by default;
no setup is needed. Any other RSS/Atom feed can be added on the Sources page (internal addresses are refused). The CERT-FR
feed ships disabled: it covers vulnerabilities, not leaks.

## Responsibility

You are responsible for complying with the terms of use of every source you enable. OpenDLM identifies itself with a clear
User-Agent, uses official APIs only, and never stores leaked content.
