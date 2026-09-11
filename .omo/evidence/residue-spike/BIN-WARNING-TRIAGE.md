# BIN-WARNING-TRIAGE — npm publish `"bin[border]" script name dist/index.js was invalid and removed`

Date: 2026-09-11. Scope: 100% local (npm 11.19.1, node v22.22.1). No pushes, no CI dispatches, no gh.

## Verdict

**Publish-time normalization noise, not an artifact defect — but the repo carried a non-canonical
form, so we removed the root cause.** `./dist/index.js` in the repo `package.json` was accepted,
silently rewritten to bare `dist/index.js`, and the rewritten value is what the registry manifest
held (hence `npm view border-customs@{0.4.0,0.4.1} bin` → `{border:'dist/index.js'}` with no `./`).
The warning's own wording ("invalid and removed") is a legacy misnomer: the bin entry is **replaced
with the normalized target, never dropped** from the published manifest, and the **shipped tarball's
package.json was never touched at all**. Fix applied: `package.json:8` `"./dist/index.js"` →
`"dist/index.js"` (the canonical pass-through form). Publish is now warning-free — verified with
`npm publish --dry-run` on this repo: zero `warn publish` lines.

## Mechanism (primary sources, npm 11.19.1 installed CLI)

- `npm/lib/commands/publish.js:279-287` `#getManifest(spec, opts, logWarnings)`: for a **directory**
  spec it calls `pkgJson.fix(fetchSpec, { changes })` and, only with `logWarnings=true`
  (second call at `publish.js:124`, after the pack leg), prints
  `log.warn(this.#command, 'npm auto-corrected some errors in your package.json when publishing.
  Please run "npm pkg fix" to address these errors.')` + `errors corrected:\n...`.
  The first manifest fetch (`publish.js:97`) runs the same fixer with warnings suppressed.
- `@npmcli/package-json/lib/normalize.js:31-84` `normalizePackageBin`:
  - line 57 `binTarget = secureAndUnixifyPath(pkg.bin[binKey])`;
  - lines 69-71 push the `"bin[base]" script name ... was invalid and removed` change note **iff
    `binTarget !== pkg.bin[binKey]`** (i.e. the form changed);
  - line 72 `pkg.bin[base] = binTarget` — the normalized target is then **assigned back**, so the
    entry survives in the published manifest. Actual deletion only happens when
    `secureAndUnixifyPath` returns `''` (empty target, lines 59-63) or the base name is empty
    (lines 50-55); an emptied `bin` object loses the key entirely (lines 75-78).
- `normalize.js:131-134` `secureAndUnixifyPath(ref) = path.join('.', path.join('/', unixify(ref)))`,
  `''` if it starts with `./`: clamps `..` escapes and drive letters into the package root and
  **normalizes every form to a bare relative path** — `./dist/index.js` → `dist/index.js`,
  `/dist/index.js` → `dist/index.js`. Pass-through (no note) ⇔ already bare relative.
- `@npmcli/package-json` `.fix()` is invoked by publish; `npm pack` (via libnpmpack) does **not**
  rewrite the manifest — `npm pack --dry-run` and a real `npm pack` here emit zero bin warnings
  and the tarball's `package/package.json` keeps the **raw** form verbatim (see matrix).
- Install side normalizes silently: `npm install <tarball-with-'./'-bin>` creates the `.bin` shim
  without any warning (fixture + real-border pack legs below).
- Docs: `npm/docs/content/configuring-npm/package-json.md` §bin canonical example is
  `{"bin": {"myapp": "bin/cli.js"}}` — **bare relative**, no `./`. `npm-pkg.md:127-128`:
  "Auto corrects common errors in your package.json. npm already does this during publish, which
  leads to subtle (**mostly harmless**) differences between the contents of your package.json file
  and the manifest that npm uses during installation." — npm itself labels this noise class harmless.
- Warning origin in CI: `.github/workflows/publish.yml:230` runs `npm publish --provenance
  --access public` on the **directory** (not a staged tarball file), which is exactly the
  `spec.type === "directory"` branch that logs. The `BORDER_PACK_TEST=1 npm test` leg is already
  wired at `publish.yml:143` — no workflow change needed.

## Matrix (empirical, /tmp/bintriage fixtures + real repo, npm 11.19.1)

| form in package.json | `npm publish --dry-run` warns? | packed tarball `bin` | `npm install <tarball>` shim | shim runs |
| --- | --- | --- | --- | --- |
| `./dist/index.js` | YES: `"bin[fixt]" script name dist/index.js was invalid and removed` | `./dist/index.js` (raw kept) | created | rc 0, stdout non-empty |
| `dist/index.js` | NO | `dist/index.js` | created | rc 0, stdout non-empty |
| `/dist/index.js` | YES (same note) | `/dist/index.js` (raw kept!) | created | rc 0, stdout non-empty |

Absolute is strictly worse than `./` (the tarball ships an absolute path). Bare relative is the only
warning-free form. Real repo after the flip: `npm publish --dry-run` → no warn lines;
`npm pack` → `packed bin: {'border': 'dist/index.js'}`; `BORDER_PACK_TEST=1` pack→install→
`.bin/border --help` → **2/2 pass** (shim exercised on the real artifact, `/scan/`+`/roundtrip/`
assertions intact).

## Decision + change

Change `package.json:8` to `"dist/index.js"`. Minimal + durable: kills the warning at the source
(no npmrc / CI filter / suppression hacks), and the repo source now byte-matches what the registry
manifest and every install already normalized to. `test/releaseArtifacts.test.ts` was read first —
it asserted nothing about the bin string (only dist presence + shim behavior), so the flip could not
break it; the pack test still exercises the **real `.bin/border` shim path** unchanged.

- `package.json:8`: `"./dist/index.js"` → `"dist/index.js"`.
- `test/releaseArtifacts.test.ts`: new always-on test `package.json bin uses the warning-free
  canonical form (bare relative, no './')` asserting `bin.border === "dist/index.js"` + no `./` +
  no leading `/`. TDD order honored: added first, ran RED (`not ok 1`), flipped the string, GREEN.
  Existing `BORDER_PACK_TEST=1` opt-in shim assertions untouched — they already cover
  shim EXISTENCE+EXECUTION post-install on the packed tarball (`existsSync(shim)` + non-empty
  `--help` + `/scan/`/`/roundtrip/` content), so no duplicate leg was added.

## Gates (all run this session, 2026-09-11)

| gate | result |
| --- | --- |
| `node --import ./tools/register-ts.mjs --test test/releaseArtifacts.test.ts` | 1 pass + 1 skip (opt-in gate), 0 fail |
| `BORDER_PACK_TEST=1 node --test test/releaseArtifacts.test.ts` | **2/2 pass**, 0 fail |
| `--test-name-pattern 'R4-DOC' test/residue.config.test.ts` | 1/1 pass |
| `npm test` (full, once, 146 s) | 706 tests / 693 pass / 2 fail / 11 skip / 0 cancelled — the 2 fails are exactly the known-red `C5-1 subset discipline` + `C5-4 ordering` pair (local suite, allowlist-independent) |
| `npm run typecheck` | rc 0 |
| `npm run build` | rc 0 (dist re-staged before pack leg) |
| `npm publish --dry-run` on this repo | zero `warn publish` lines |
| `npm pack` → tarball inspection | `bin: {'border': 'dist/index.js'}` |

## Residual

- The warning class itself is gone only for `bin`; if a future dependency bump makes npm's fixer
  flag another field (repo url normalization, etc.), the same `publish.js:284` "run npm pkg fix"
  path prints it — the pack-test + bin-form lock here covers bin only.
- `npm warn Unknown builtin config "globalignorefile"` fires on every npm invocation from this
  machine's ~/.npmrc — environment noise, out of package scope.
- Registry-side proof (re-`npm view` after the next release) still pending a real publish; the
  local dry-run is the strongest no-push evidence available.
