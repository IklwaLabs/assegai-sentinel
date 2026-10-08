# Contributors

Sentinel is built by IklwaLabs.

## People

| Name | GitHub | Role |
| --- | --- | --- |
| Eric Alfonce | [@ericalfonce](https://github.com/ericalfonce) | Founder, engineering, release |
| IklwaLabs | [@IklwaLabs](https://github.com/IklwaLabs) | Organisation, issue tracking |

## How this list relates to GitHub's own contributors graph

GitHub builds the contributors list shown on the repository page from **commit authorship**,
not from collaborator access and not from this file. So being named here and appearing in
GitHub's Contributors list are two separate things, and only the second one GitHub maintains.

Every commit in this repository is authored as `IklwaLabs <engineering@iklwalabs.com>`.
That is deliberate: it keeps a single, consistent, org-owned identity on the history for
release attribution and signing, rather than tying the audit trail to one person's personal
account. The trade-off is that GitHub attributes all of it to the organisation account.

If you would rather have per-person attribution on GitHub itself, the mechanism is the
co-author trailer on a commit:

```
Co-Authored-By: Eric Alfonce <your-github-verified-email>
```

GitHub links a co-author only when the address in the trailer is a verified email on a
GitHub account, so the address has to come from
**Settings → Emails** on the account, not from guesswork. Rewriting existing history to change
authors was considered and rejected: it would rewrite every commit SHA, invalidate the
`v0.1.0` tag on both remotes, and make the published release history unverifiable — a large
cost for a cosmetic gain.

## Reporting a problem

Security issues go through [SECURITY.md](SECURITY.md), which documents how to report one
privately. Please do not open a public issue for a vulnerability.