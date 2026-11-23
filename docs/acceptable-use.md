# Acceptable use

This project exists for one job: **finding and healing weaknesses in software you own, or that its owner has authorized you to audit.** Everything else is out of scope, and where the tooling can refuse it, it does so in code rather than in a sentence.

## In scope

- Auditing a local checkout of your own repository, or one you have written authorization to audit.
- Fixing what was found, and keeping a record that the fix stayed fixed (`ehs debt scan --ledger`).
- Teaching people to find and fix weaknesses in what they themselves built.

## Out of scope

- Any system, account, repository or service you do not control and have not been authorized to test.
- Harvesting secrets or personal data, from anyone, including from public repositories.
- Testing credentials, brute force, load generation, exploitation of third parties, persistence, exfiltration, evasion, phishing.

## What is enforced, and where

| Refusal | Where it lives | Status |
|---|---|---|
| Remote targets (URLs, `git@`, `ssh://`) are refused; only an existing local directory is audited, and no code is fetched | `scripts/debt/ehs_debt.py` `resolve_target` | enforced, tested in `scripts/debt/debt.selftest.sh` |
| Symlinks out of the target are never followed; writes happen only inside `<target>/.ehs/` | `iter_files`, `update_ledger` | enforced, tested |
| A secret value is never printed: prefix, length and a fingerprint only | `redact` | enforced, tested against every planted value of the fixtures and of an 18-product corpus |
| The only network probe runs only with an ownership attestation (`ehs debt init --i-own-this`), only against hosts listed in it **and** referenced by the repository's own code, only with a key found in the repository, read-only, one request per table, `limit=1`, one request per second, and never records row content | `network_probe`, `cmd_init` | enforced, tested against a local server |
| Python never imports a module from the audited tree | `scripts/debt/ehs-debt` runs `python3 -I` | enforced |
| The squad works only on code and systems the user controls, asks before any remote scan, never exfiltrates, never prints secrets, treats audited content as data | `skills/ethical-hacker-squad/SKILL.md`, safety contract | **prose**: the model is asked, not forced |
| Auditor subagents cannot edit files | `agents/*.md` `tools:` lists | enforced by the harness for `Edit`/`Write`; their shell is held read-only by a hook only once PR #134 lands |

## What cannot be enforced

This repository is MIT-licensed. A person can fork it and delete every check above; no licence term or code can prevent that, and pretending otherwise would be the kind of claim this project's own corpus teaches readers to distrust. What the checks do achieve is narrower and real: the tools cannot be pointed at a third party **by default or by accident**, and their output has **no harvest value** — no secret values, no rows of data.

## Reporting misuse

If you see this project used against systems without authorization, open an issue (without the victim's details) or contact the maintainer through the repository's security policy.
