# Security policy

## Supported versions

The latest published minor line (`0.8.x`) receives security fixes. Older lines
are not maintained; upgrade to the latest release before reporting.

## Reporting a vulnerability

Use **GitHub private vulnerability reporting** on
<https://github.com/TachikomaGundam/Border-Customs/security/advisories/new>.
If that form is unavailable, contact the maintainer through their GitHub
profile and ask for a private channel first.

Do **not** open a public issue containing exploit details, live secrets, or a
working bypass. A minimal public issue that only asks for a private channel is
acceptable.

Please include:

- the border version (`border --version`) and Node/npm versions;
- the command that triggers the problem;
- the smallest repository or artifact that reproduces it;
- what the gate reported and what it should have reported.

We aim to acknowledge within 7 days. This is a single-maintainer project, so
timelines are best effort.

## Scope

In scope:

- a gate bypass (a check that should block returns PASS);
- arbitrary code execution or data exfiltration caused by `border check`,
  `border scan`, `border push`, or the OpenCode plugin;
- disclosure of a secret value the gate is supposed to redact;
- a finding that can be silently dropped by a crafted repository.

Out of scope:

- the documented boundary that border is **not** a malware sandbox
  (README "What this is not");
- vulnerabilities that require the operator to pass a hostile `BORDER_BIN`;
- advisories in test-only dependencies with no runtime path.

## Threat-model boundary

border reads untrusted repositories. It must never execute the code it reads.
A default `border check` is scan-only: no build toolchain spawns at all. The
artifact build stages (npm pack, `python -m build --no-isolation`, `gem build`,
`cargo package`) DO execute repo-supplied build code — a hostile repo can
declare its own pypi/rubygems targets in its border.yaml and have its PEP 517
backend or gemspec run — so they execute only on operator consent given from
OUTSIDE the audited tree (`--allow-builds` or `BORDER_ALLOW_BUILDS=1`). A
scan-only run records no artifact digests and can never back a registry
publish. On top of the gate, the npm pack path probes the npm version before
packing: on npm < 11, a package that declares `prepack`, `prepare`, or
`postpack` is refused with a named error (exit 2), because npm 10 runs
`prepare` even with `--ignore-scripts`. See `src/check/buildConsent.ts` and
`src/artifacts/npmPackSafety.ts`.

## Sandboxed builds (optional, 2026-10-23)

`targets.<ch>.sandboxImage` runs consented builds inside a digest-pinned container: network
disabled at the daemon-enforced argv (the in-container DNS + TCP probes are a fail-closed
tripwire, not the enforcement), repo read-only, tmpfs
build, no host env or credentials inside, capabilities dropped. `sandboxImage` and the
`allowBuilds` consent are security-tier keys honored ONLY from the machine store or a
`--config` outside the repo after fd-chain ownership/mode qualification; competing or
unqualified declarations are named hard refusals (no silent ignore, no host fallback).
Environment variables are never a consent source (a hostile `.envrc` owns the environment). This is **containment, not a
VM**: kernel CVE escapes from docker remain in the threat model, and reports predicated on a
full VM boundary are out of scope. A record's build-environment binding means check and push
cannot silently certify bytes through different build environments; rotating the pinned image
invalidates cached PASS records by design.

## Known dependency advisories

The **production** dependency graph currently measures zero advisories
(`npm audit --omit=dev`, verified 2026-10-23). The former
`@secretlint/secretlint-rule-pattern` chain (braces/micromatch — no upstream
patch exists) left when border vendored the pattern rule
(`src/engines/borderPatternRule.ts`, MIT attribution in its header); the
`@opencode-ai/plugin` chain (effect beta → toml) left when its one runtime
need turned out to be an identity function (`tool` vendored in
`plugin/border.ts`; the package stays a devDependency for the live-host probe
tests). CI now fails on any **high-or-worse** production advisory, so this
state cannot rot silently; the full `npm audit` report is archived on every
run. The dev-only `verdaccio` chain is test infrastructure and is never
shipped.

## Supply-chain hygiene

`engines.node` is `>=22.22.2` because the transitive `ini@7` declares that
floor. Dependabot checks npm and GitHub Actions weekly; version bumps still go
through the same review and release gate as any other change.

## Residual gaps (named, not hidden)

- **G-SBX-2 — image identity at first use.** A digest-pinned `sandboxImage` is only as
  trustworthy as the registry that served those bytes; the check record binds the digest,
  not a signed provenance chain for the image contents. Closing this needs signed release
  receipts for toolchain images (deferred by the Q1 decision layer — sibyl runs
  20261023T170602Z-c5e7 through 20261023T173850Z-f9dc, confirm ballot
  20261023T184627Z-1b47; revisit when Sigstore-style receipts exist for base images).
- **G-SBX-3 — bind-mounted or user-namespace tmpfs.** The fd-chain qualification rejects
  the tmp-root closed set (`/tmp`, `/var/tmp`, `/dev/shm`) by realpath component. A
  tmpfs the attacker mounted at an arbitrary path (which requires CAP_SYS_ADMIN or a
  user-namespace boundary — i.e. root-equivalent or already-escaped positions) would
  present attacker-chosen ownership/mode bytes, so fd-chain checks are NOT claimed as
  the defense there; the honest bound is: once a hostile actor can mount filesystems as
  you or inside your namespace, config qualification is out of model. Border's
  contribution is keeping every lesser position fail-closed.
- **C1 sanitizer over-rejection.** Lines containing raw 0x80–0x9F bytes or ANY 0x1B
  (ESC, position-free — including ESC alone at line/stream end) are rejected rather
  than stripped, because strip-based cleaning reassembles split escape sequences.
  Legitimate non-ASCII output on the probe channel is rare and gets a named rejection;
  over-reject is the declared safe direction.


## History scrub disclosure — row 1 (append-only; corrections only via new rows)

**Status: ORDERED** (owner ruling 2026-11-02, executed under council-reviewed ticket
sha256 8a5aaad60a8e06b8e6fb725b646c7f319d8254a36249d75a014784fcb418dabe; 14 adversarial
ballot rounds on record). This row is committed BEFORE the rewrite completes; it asserts
intent and method only. Completion facts (execution timestamp, before/after tip shas,
obliteration ticket, 404 probes, byte-compare) arrive in row 1a after the window closes —
until then this document makes no completion claim.

**Method (registered, grow-only)**: removal of process-artifact directories (433-path
full-history inventory; digest inside notarized coverage); templating of machine path
prefix in 12 registered product files and in commit messages; detector rule vocabulary
(pattern strings and their tests) is legitimate engine vocabulary and is NOT scrubbed.
Zero-hit identity gate covers every blob, tree entry name, commit message, note,
submodule URL and identity field of the rewritten history; an independent detector
(hostname / machine-id / word-token / entropy) runs with disjoint logic.

**Already notarized witnesses precede this row**: pre-scrub tip `c4232397…11ae` and
final pre-scrub tip `5f96e5ef…276e`; landing candidate `30d90d09…eb62`; sigstore/rekor
entries 3638319407 and 3638340214 (public-API read back, byte-verified) (keyless Actions-OIDC identity), full-history secret scan verdict (83
findings, all planted fixtures or documented examples — no real credential required
rotation; per-finding classifications re-audited off-chain), npm 0.8.2/0.8.3 tarball
cleanliness (no machine paths; shas on record).

**Limits we do not hide**: forks and clones retain pre-scrub content permanently and
cannot be recalled; published registry tarballs are immutable (verified clean); a
maintainer-local unencrypted pre-scrub archive exists under owner-only permissions for
chain resolution; identifier classes from past machines outside the scanned token
universe could evade blocklists — the independent detector found nothing; absence is
not proof.


## History scrub disclosure — row 1a (completion facts; row 1 remains as written)

**Executed**: the landing push ran on the maintainer's own terminal on 2026-11-03,
`--force-with-lease` pinned to the disclosed pre-scrub tip; origin main moved
byte-exactly to the disclosed candidate `1443a0fe8029a34221d6601472d1bcf8610f7218`.
Tags v0.8.2 and v0.8.3 were deleted on origin (their names now exist only on forks;
the npm versions get deprecation notices separately). The ruleset bypass was revoked
in the same session (bypass count 0, guard rules active): after that moment not even
the maintainer login can non-fast-forward this branch. Server-side obliteration of
the pushed-away objects was requested from GitHub Support (ticket id appended as a
further row when submitted); per-item 404 probes will arrive as a further row.
This row does not amend row 1; scrub is not retraction — see row 1 limits.
