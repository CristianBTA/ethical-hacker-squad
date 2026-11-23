# The next step: from finding the debt to closing it, with proof

Status: **2026-11-22. Sections 1-8 are the evaluation and proposal as written before any code. Section 9 is what was then built, measured and discarded; read it first if you only want the result.**
Method: a peer survey read from the repositories (not the taglines), a 2025-2026 evidence survey of what vibe coding leaves behind, and this repository's own results. Numbers from vendors who sell the fix are marked as such; a claim whose source could not be read is marked `unverified`.

## 1. Where this project actually stands

Our own bench says the corpus does not beat the model alone at detection, and that the plugin lost to a plain guide in the educational round of 2026-11-09 (recall 0.913 against 0.936, clean controls 0.5 against 1.0, 42 % dearer). Every proposal below is judged against that result: **more detection knowledge is not the step.** The corpus already holds the knowledge for this debt (`WEB-19`, `MOB-11`, `INF-03`, `PRV-04`, `SUP-16..18`, `WEB-22`). What it does not hold is anything that outlives one run.

The comparison of 2026-08-22 is stale: four of its subjects moved (`AI-Infra-Guard`, `mantis`, `ultrasec`, `BreachPilot`), and `competitive-discovery.sh` reports four unresolved candidates (`Claude-AgentHunter`, `asvs-auditor`, `auditor-zk-skills`, `security-audit-skills`).

## 2. What peers do better (read on 2026-11-22)

| Capability | Who | What we lack |
|---|---|---|
| Fix inside the loop, with an adversarial re-check | `google/mantis`, `openai/codex-security`, Trail of Bits `patching-bugs` | our remediator patches per finding, then a verifier judges by reading |
| Deterministic sensors under the model, ranked by EPSS/KEV | `maxgfr/ultrasec`, Ship Safe | a repeatable pre-pass (PR #136 has one, unmerged) |
| Stack-specific probes (Supabase RLS, public bundle secrets) | Ship Safe, Supabase `splinter`, small BaaS scanners | procedures exist (PR #125, unmerged) but no probe that runs |
| Prevention at generation | CoSAI Project CodeGuard, hook guards | nothing before the code exists |
| Standards mapping in CI | `asvs-auditor`, Anthropic's Action | PR review recipe only (PR #137, unmerged) |
| Honest outcome vocabulary | Ship Safe: `resolved / neutralised / inconclusive / regression_detected`, and `verified` stays false without an independent retest | our states are finding states, not fix states |

## 3. The job nobody does

No peer delivers **verified remediation of existing debt over time**: fix, independent proof it closed, regression check, a record that survives the session, and a measured closure rate. Ship Safe says its own fixes are never verified. Mantis publishes no patch rate and calls its PR Action untested. Independent fix quality is poor: about 26 % of generated patches fix fully without changing behaviour (1Password), and one study found 95 % of patches compiled while none fixed the weakness. (Both secondary; read the sources before quoting.)

That is the gap, and it is the right one for this project because it is the only place our existing strengths apply: a verifier that is a different agent, negative evidence, an honest "I could not decide".

## 4. The debt, ranked by evidence, with the check a script can run

Vendor-sourced unless stated. `Auto` = a script can verify closure without a model.

| # | Debt | Evidence | Durable control | Auto |
|---|---|---|---|---|
| 1 | BaaS rules missing (Supabase RLS, Firebase) | strong: CVE-2025-48757, Moltbook (Wiz) | deny-by-default RLS + policy tests | yes: anon-key probe per table and bucket expects 401/empty |
| 2 | Object-level authorization | strong: Base44, Lovable BOLA (scope disputed) | one central authz layer | yes: user A requests user B's ids, expects 403 |
| 3 | Secrets in code and bundles, never rotated | strong: GitGuardian 2026 (64 % of 2022 secrets still valid) | server proxy, secrets manager, rotation, push protection | yes for presence; rotation age partial |
| 4 | Agent / MCP injection, config code execution | strong: Claude Code CVE-2025-59536, Amazon Q CVE-2026-12957 | no `service_role` to agents, project-scoped read-only MCP, reviewed configs | partial: lint `.mcp.json`, hooks, broad keys |
| 5 | Dependency supply chain | strong: Shai-Hulud waves | lockfile + `npm ci`, `ignore-scripts`, release-age rule, provenance | yes |
| 6 | Hallucinated packages | moderate: rate is model- and prompt-specific | registry existence and age gate on new deps | yes |
| 7 | Destructive agent access, untested backups | moderate (the 2026 case rests on one founder's account) | env separation, scoped tokens, off-platform backups, restore drill | yes: restore into scratch |
| 8 | Key, IV and password handling, JWT | moderate | argon2id, KMS/envelope, pinned JWT alg with random secret | yes: rules, wordlist, hash prefix, IV reuse |
| 9 | Injection, SSRF, business logic | strong rates | auto-escaping, egress allowlist, server validation | yes DAST; logic only partial |
| 10 | No rate limits or caps | moderate | gateway limits, quotas | yes: burst expects 429 |
| 11 | PII exposure, retention, logging | moderate | data inventory, TTL/purge, field encryption, redaction | partial |
| 12 | Headers, TLS/HSTS, CSRF | moderate, small sample | hardened edge config | yes |

**Encryption, stated honestly:** models choose algorithms well (Veracode: about 87 % pass on algorithm choice). The debt is in key and IV management, password hashing and JWT secrets. **Encryption at rest, backup quality and monitoring have no study measuring them in AI-built apps.** They are unevidenced, not absent, and the plan must not claim otherwise.

## 5. Proposal: a debt ledger with executable probes

Five pieces, smallest first. Each is independently shippable.

1. **Probe-as-code for the `Auto` rows.** One small stdlib script per row (anon-key RLS probe, cross-tenant request template, bundle secret grep, lockfile and `ignore-scripts` check, new-dependency existence and age, JWT secret and algorithm check, header and TLS check, rate-limit burst, agent-config lint). Deterministic, zero model cost, runnable in CI. Network probes only against a target the user names, under the existing authorization rule.
2. **A ledger the repository keeps** (`.ehs/debt.json`, one entry per debt item): `open | closed | unknown`, the probe that decides it, the date and commit it last ran at. `unknown` is a first-class state, so silence never reads as clean. Re-running is the product: a closed item that reopens is the finding.
3. **Fix outcomes, not finding states.** Adopt `resolved / neutralised / inconclusive / regression_detected`; `verified` is true only when an agent other than the fixer ran the probe against the patched tree and a regression test failed before the patch and passed after (the rule `ehs-remediator` already states).
4. **Handover pack for what we must not do.** Rotating a secret, purging history, enabling KMS and changing remote infrastructure stay outside the safety contract. The pack states the exact steps, the owner, and the probe that confirms afterwards (for a secret: the old credential is rejected). The ledger entry stays `open` until that probe passes.
5. **Prevention, small and honest.** A `PreToolUse` guard for secrets in writes and `NEXT_PUBLIC_*` holding a secret, plus a short rules file. Documented as client-side and bypassable; it lowers the rate, it proves nothing.

Not in scope: new corpus procedures for the 12 rows (they exist), and any claim of secure systems.

## 6. How we would know it works (pre-registered)

- **Instrument:** paired fixtures, each a vulnerable app plus a safe control, one pair per `Auto` row, built here and checked into `bench/`, plus at least one third-party corpus so the numbers are not only ours (`ultrasec` reports OWASP Benchmark per CWE; the same discipline applies).
- **Arms:** the unaided model, the plugin as it is, and the plugin with the ledger and probes. Same model, same cap.
- **Metrics:** fix-closure rate (probe passes after the patch), regression rate, false-closure rate (ledger says `closed`, probe says open), cost against the unaided model.
- **Bands fixed before the numbers**, as in `bench/runs/2026-08-22-third-competitor`. If the ledger arm does not beat the unaided arm on closure at a cost no higher than 1.2x, this proposal is withdrawn and the withdrawal published, as the project has done three times.
- **Refresh the comparison:** re-pin the four moved products, resolve the four unresolved candidates in `docs/competitive-baseline.json`, and run `competitive-freshness.sh` and `competitive-discovery.sh` on a schedule (PR #141's weekly gates are the place), so "evaluate against peers" is a recurring check rather than a photograph.

## 7. Constraints that already exist

- Protected paths (`agents/**`, `hooks/**`, `scripts/hooks/**`, `scripts/gates/**`) need the maintainer's `override/g7-reviewed` label. The guard hook and any agent edit fall there.
- `SKILL.md` budget is 12,288 B; the served tree admits only `.md` and `.json`, and PR #141 targets 1 MB. A large engine does not fit (an earlier 2.4 MB attempt was lost, see the maintainer notes). Probes must stay small stdlib scripts, shipped outside the served tree if needed.
- Build order depends on open PRs: #132 (integration), #125 (BaaS procedures), #136 (pre-scan) and #141 (slim distribution) should land first or the work stacks on them.

## 8. Risks

- The ledger arm may not beat the unaided model. That is a possible, publishable result.
- Probes against live systems need explicit authorization; a probe that touches production is a safety-contract violation, so the default target is a local or staging instance.
- Most evidence above is vendor-sourced and some of it is unverified. The ranking is directional, not a prevalence estimate.

## 9. What was built and measured (2026-11-22)

Built: `scripts/debt/ehs_debt.py` (`scripts/ehs debt scan|status|init`), proposal pieces 1 to 3 plus the scope guard of `docs/acceptable-use.md`. Pieces 4 (handover pack) and 5 (prevention hook, a protected path) are not built. Nothing in the served tree (`skills/`, `agents/`) changed, so the plugin a user installs is byte-identical and its measured result cannot have moved.

### Method

Three rounds. Before each one the keep rules were written down and the probes frozen in a commit, and only then was the corpus opened:

| Round | Frozen at | Corpus | Written by |
|---|---|---|---|
| 1 | `4098814` | 18 products, sealed answer key, 3 clean controls | the 2026-11-09 educational round |
| 2 | `5c16d3f` | 11 products, 39 defects, 39 decoys, 3 clean controls | a fresh agent that never read the probes |
| 3 | `a86f1d9` | 12 products in other stacks (SvelteKit, Expo, Kotlin, Go, Laravel, Astro, Spring, Deno, Swift…), 43 defects, 45 decoys, 3 clean controls | a fresh agent that never read the probes nor corpora 1-2 |

Every finding was judged by two blind Sonnet judges against the sealed key, and counted true only if both said so; they disagreed on 0 of 125 findings. In round 3 every finding of a new rule was also re-read in the code by the maintainer's agent.

Keep rules: precision >= 0.80; zero findings of medium or high severity on any clean control; a probe without corpus signal kept only if it passes its own vulnerable/safe fixtures (K3); no secret value in the output (K4: 0 of 52 planted values across the three corpora ever printed).

### Result

| Probe | Precision (both judges) | Decision |
|---|---|---|
| DEBT-01 BaaS write / all-row exposure, v2 | 13/13 (rounds 2-3) | kept. v1 discarded at 0.60: public-read catalogs |
| DEBT-02 provider secret in client or mobile code, v2 | 2/2 (round 3) | kept. v1 discarded at 0.58: env names that merely mention a provider, Firebase web keys |
| DEBT-03 provider secret in server code, v2 | 13/13 (rounds 2-3) | kept. v1 discarded at 0.67: Firebase web keys |
| DEBT-04 fast password hash / clear compare | 6/6 base, 1/1 v3 | kept |
| DEBT-05 JWT unverified or short literal secret | 4/4 base, 1/1 v3 | kept; one v3 rule (`jwt.ParseUnverified`) discarded, it failed its own fixture |
| DEBT-06 non-crypto random for codes | 1/1 base, 3/3 v3 | kept |
| DEBT-07 broken encryption | 4/4 base, 1/1 v3 | kept |
| DEBT-08 agent / MCP configuration | 8/8 | kept |
| DEBT-09 dependencies not locked | 20/21 | kept |
| DEBT-10 debug mode / CORS with credentials | 6/6 base, 1/1 v3 | kept; the v3 "manual CORS headers" rule reverted: 0/1 and it fired on a clean control |
| DEBT-11 credentials in logs | 2/2 base, 1/1 v3 | kept |
| DEBT-12 TLS verification off | 3/3 base, 1/1 v3 | kept; one v3 rule (Kotlin `hostnameVerifier`) discarded, it failed its own fixture |
| DEBT-13 SQL from interpolated values, v2 | no corpus signal (0 findings, 0 false) | kept on fixtures only. v1 discarded at 0.17 with four false highs on a clean control |

Recall, for honesty about what it misses: 29 of 39 defects on corpus 2 and 32 of 43 on corpus 3 were found by some probe. Missed on corpus 3: all three SQL injections (Go `Sprintf` with `'%%%s%%'`, a Laravel `whereRaw` fragment, Java concatenation after a `%`), three debug/CORS cases (gin debug mode, two handlers reflecting an `origin` variable), two credentials in logs, one JWT, one unpinned dependency and one client secret. Many v3 rules have fixture evidence only; small numbers per probe (n = 1 to 21) are a band, not a ranking.

### What this does not show

That a model with the ledger closes more debt than a model without it. That was proposal step 6 and it was not run: it costs model runs and it was not needed to decide what to keep, because nothing here changes what the plugin does. It is the next measurement, and the bar written in section 6 still applies.
