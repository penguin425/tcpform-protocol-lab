# Security Policy

## Supported versions

Security fixes are provided for the latest `0.1.x` release and the `main`
branch. Older prerelease snapshots may not receive fixes.

| Version | Supported |
| --- | --- |
| Latest `0.1.x` | Yes |
| `main` | Yes |
| Older versions | No |

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Email
`penguin@valuemix.jp` with the subject `tcpform security report` and include:

- the affected version or commit;
- the impact and attack scenario;
- reproduction steps or a minimal proof of concept;
- any suggested mitigation;
- whether and when the report may be publicly disclosed.

Remove credentials and identifying packet data before sending a report. If a
reproduction requires sensitive material, first ask for a secure transfer
method.

You should receive an acknowledgement within 7 days. The project will validate
the report, coordinate a fix and release when appropriate, and credit the
reporter unless anonymity is requested. Please allow 90 days for coordinated
disclosure unless a different timeline is agreed.

## Security scope

Reports about parser crashes, malformed packet handling, raw-socket privilege
boundaries, plugin isolation, signature verification, TLS validation, bundle
integrity, authentication, and unintended disclosure of captured traffic are
in scope. General support requests and findings that require already-compromised
administrator access should use the normal issue tracker.

