# Contributing

## Requirements

- Node.js **>= 22.22.2** (the transitive `ini@7` dependency requires it;
  `package.json` `engines` matches).
- npm (Node 22 ships npm 10, Node 24 ships npm 11 — both are supported and
  both run in CI).
- git, on `PATH`.

## Setup

```bash
npm ci
npm run typecheck
npm test
```

`npm test` runs the full suite with the TAP reporter and is fail-closed: any
red fails the run. On a machine without the external engines below, whole test
files fail loudly by design (the guards never skip). Use the subset commands
in the next section while developing.

## External engines used by the suite

The full suite requires the toolchain below. Versions are pinned because the
acceptance tests assert them.

| Engine | Version | Provisioning |
| --- | --- | --- |
| gitleaks | 8.30.1 | download the `linux_x64` release to `~/.local/bin/gitleaks`, `chmod +x` |
| cargo | system | install Rust via rustup |
| gem (RubyGems) | system | install `ruby-full` |
| docker | system | only the opt-in roundtrip legs (`BORDER_*` docker flags); the offline suite skips them |
| verdaccio | devDependency | installed by `npm ci` |
| python `build` | 1.6.0 | `python3 -m pip install --user --break-system-packages build==1.6.0` |
| python `twine` | 7.0.0 | `... twine==7.0.0` |
| python `wheel` | 0.46.3 | `... wheel==0.46.3` |
| python `setuptools` | 78.1.1 | `... setuptools==78.1.1` |
| python `httpx` | 0.28.1 | `... httpx==0.28.1` |

Git is also required for the tarball/status tests; run from a real checkout,
not an exported source tree.

## Running a subset

Every file is runnable on its own:

```bash
node --import ./tools/register-ts.mjs --test --test-reporter=spec test/<file>.test.ts
```

| Area | Files | Needs |
| --- | --- | --- |
| core gate, config, ledger, report | most `test/*.test.ts` | Node only |
| secret scanning | `engines.secretlint.test.ts`, `engines.gitleaks.test.ts`, `scan*.test.ts` | gitleaks 8.30.1 |
| npm artifacts / registry | `artifacts.npm.test.ts`, `check.artifacts.test.ts`, `residue.npm.test.ts`, `channels.integration.ts` | npm; verdaccio for registry legs |
| crates | `channels.crates.test.ts`, `residue.crates.test.ts` | cargo |
| RubyGems | `channels.rubygems.test.ts`, `residue.gem.test.ts` | gem |
| PyPI | `artifacts.pypi.test.ts` | python `build` + `twine` |
| roundtrip docker legs | `roundtrip.*.test.ts` | docker, opt-in only |

The guards live in `test/helpers/require-engines.ts` and in the channel test
files. A missing engine is an error, never a skip.

The full suite takes roughly 15 minutes on a developer box. CI runs it on Node
22 and Node 24 for every push to `main` and every pull request.

## Consuming border (dev boxes included)

Run gate code from a pinned install — `npm install -g border-customs@<version>` or a
one-off `npx border-customs@<version> check` — not from a source checkout's `dist/`.
Records carry `engineBuild` (`version+commit[.dirty]`, printed by `border --version`), so an
unpinned or dirty bundle is visible on every verdict it produces; a `.dirty` record is a
finding, not a style note. Building a local bundle for development is fine
(`npm run build` stamps it); letting another repo's CI or your shell habit depend on one
is not — that is the consumption shape the 2026-10-23 decoupling audit named.

## Execution consent (build stages)

`border check` runs scan-only by default: zero build toolchains spawn unless the
operator consents with `--allow-builds`, or `allowBuilds: true` in the machine store / an
out-of-repo `--config` (see `src/check/buildConsent.ts` + the §3 security tier in
`src/tier.ts`). The environment is deliberately NOT a consent source — `BORDER_ALLOW_BUILDS`
was removed before any release because `.envrc`/direnv makes env a repo-influenced channel.
The suite passes consent explicitly in the
test fixtures that build, so nothing extra is configured to run the tests. When you run
border yourself on a repo with registry targets and need artifact digests (a prerequisite
of `border push`), pass the flag. Never place consent in a scanned repo's config or
scripts — a repo consenting to its own execution is exactly the hole this gate closes.

## Sandboxed-build development (optional)

`targets.<ch>.sandboxImage` runs consented builds in a digest-pinned container
(`src/artifacts/sandbox.ts`). To try it locally:

```bash
docker pull node:22                          # or python:3.12-slim / rust:1 / ruby:3.3-slim
docker image inspect --format='{{index .RepoDigests 0}}' node:22   # copy the sha256 pin
```

Put the printed `name@sha256:<64hex>` reference into your machine-side config (never a tag —
the schema rejects it). Lane notes: the pypi image needs `build`+`setuptools`+`wheel` installed
(no network inside); the crates lane downloads registry index data on first build, so warm it
once by running a consented crates check (cache persists in `.border/cache/`). The probe
requires one of getent/curl/python3/node/ruby in the image — all official lane images ship
several; a zero-probe image fails closed with a named error, by design.

Tests never spawn real docker: `test/sandbox.test.ts` scripts the `DockerExec` seam and pins
the docker argv token by token — extend that file when touching the containment contract.

## Changing the version

Do not hand-edit version literals. `npm version <patch|minor|major>` runs
`tools/version-sync.mjs`, which rewrites every tracked literal (package.json,
both lock roots, the plugin header, the scan User-Agent, and the README install
pin). To verify without writing:

```bash
npm run version:check
```

Historical changelog entries and release receipts are records and are never
rewritten.

## Pull requests

- Add or update a test for every behavior change. The suite is the contract.
- Keep failures closed: a new external dependency needs a presence guard and a
  provisioning note in this file.
- Run `npm run version:check`, `npm run typecheck`, and the relevant test
  subset before opening a PR. CI runs the full suite.
- Do not commit secrets, live tokens, or machine-specific absolute paths.
- Security reports go through `SECURITY.md`, not the public issue tracker.

## Where things live

- `src/` — the CLI and gate engine.
- `plugin/` — the OpenCode server plugin (V1/V2 shapes).
- `test/` — the acceptance suite (TAP).
- `tools/` — build and release helpers.
- `handoffs/` — operator/agent handoff records.
- `docs/release/` — release receipts (historical records).
