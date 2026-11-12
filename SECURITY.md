# Security policy

OpenDLM handles sensitive information (monitored addresses, API keys, alert channels), so security reports are welcome.

## Reporting a vulnerability

Please **do not open a public issue** for a security problem. Use GitHub's
[private vulnerability reporting](https://github.com/Eizi0/OpenDLM/security/advisories/new) instead.
Include the version or commit, the steps to reproduce, and the impact you expect.

You can expect an acknowledgement within a few days. Fixes are released as soon as they are ready and credited
to the reporter unless you prefer to stay anonymous.

## Design choices worth knowing

- Leaked content is never stored: only the affected address, the breach name, its date, the source and the kinds of data exposed.
- Passwords are hashed with scrypt; sessions are signed; login attempts are throttled.
- Feed URLs added by users are fetched server-side, so internal and private network addresses are refused.
