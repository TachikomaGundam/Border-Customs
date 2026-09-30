# F-REGISTRY-VANISH-2026-09-30 — v0.8.0 publish accepted by CI, absent from registry ≥30 min (DISPUTED state, no re-roll)

owner pushed main+tag v0.8.0 at ~13:46Z. CI run 36724225593 (job 36724225954) fully green:

## Write side (proven)
- step 9 release gate: "release gate green: 856 tests / 841 pass / exactly 2 sanctioned failure(s) matching the allowlist"
- step 11 pack: shasum `cec93f30866b2e4f871d06344f63585a0ce1261e`, integrity sha512-NHdH24sX5ILm6…hSZIOGkPzpBNQ==
- step 12 `npm publish --provenance --access public`: "Publishing to https://registry.npmjs.org/ with tag latest and public access"
  → "publish Signed provenance statement…" → "Provenance statement published to transparency log"
  (https://search.sigstore.dev/?logIndex=3019754891) → **`+ border-customs@0.8.0`** → step success
- step 15 consumer-refresh ritual: success
- rekor entry 3019754891 independently fetched this session: kind=dsse, envelopeHash 06fb495d…,
  payloadHash 292cbc74…, OIDC cert verifier present (raw in /tmp/rekor2.json → archived alongside)

## Read side (all independent paths, all agree: version absent)
| probe | result | time |
|---|---|---|
| full doc `registry.npmjs.org/border-customs` | `_rev: 13-c636c024da04f4091bfbcd3b4c69581c` **unchanged from pre-publish**, versions=11, latest=0.7.1 | 13:55 → 14:16Z repeated |
| `/-/package/border-customs/dist-tags` | `{"latest":"0.7.1"}` | 14:02Z |
| install-v1+json accept-header metadata | latest 0.7.1, no 0.8.0 | 14:16Z |
| tarball HEAD `/border-customs/-/border-customs-0.8.0.tgz` | 404 | 14:07Z |
| unpkg CDN `border-customs@0.8.0/package.json` | "Package version not found" | 14:02Z |
| `npm view border-customs@0.8.0 --registry=https://registry.npmjs.org` (fresh, log 14:08:51Z) | E404 | 14:08Z |

## Assessment (fail-closed, honest)
The npm CLI printed the success receipt AND a signed provenance statement reached the public
transparency log referencing this build — yet the package document's rev never moved for 30+ min
across every read route including the strongly-consistent dist-tags endpoint. A doc PUT that
returned 2xx without persisting is not a normal npm outcome; a same-day auto-rollback would
still bump _rev. This machine cannot adjudicate further from the read side.

## Explicit non-actions (doctrine: indeterminate ⇒ stop, no budget-grinding)
- NO re-publish attempt (double-vehicle class incident of 0.2.6 era is the named precedent).
- NO tag move/delete-recreate (v0.7.0-skips-number precedent; tags are the provenance anchor).
- Lease: released after push landed (law semantics) — any future publish leg re-acquires.

## Owner options (decision stays in human terminal)
1. **Wait + re-probe** (npm-side pipeline repair): `curl -s https://registry.npmjs.org/-/package/border-customs/dist-tags`
   — seat can re-check hourly and stay silent until `{"latest":"0.8.0"}`.
2. **File with npm support** (support@npmjs.com / npm community forum) quoting: package
   border-customs, version 0.8.0, CI run 36724225593, publish ts ~13:52:26Z,
   tarball shasum cec93f30866b2e4f871d06344f63585a0ce1261e, rekor logIndex 3019754891.
3. If npm confirms the write was voided: a NEW version number (0.8.1) with identical content
   would be the sanctioned republish route (v-number never reused, no force anything).

This machine's consumer posture meanwhile: this repo's config uses @latest and drift-watch is
FRESH against 0.7.1 — no stale-cache risk exists for 0.8.0 until it publishes; nothing to purge.

— Abathur, border seat. Probes verbatim above; raw CI log: /tmp/job.log (this session) + gh artifact "border-test-log".


## RESOLVED (same day, sentinel receipt 14:14:50Z)
Registry persisted the publish ~22.5 min after the CLI success line: dist-tags endpoint flipped
to {"latest":"0.8.0"} at 14:14:50Z (appended log: registry-watch-0.8.0.log), _rev moved
13-c636c024 -> 14-dde0053f. Verdict: slow-but-honest npm-side persistence pipeline, NOT a lost
write — no re-publish, no tag surgery was ever needed; the doctrine hold ("indeterminate =>
stop, no budget-grinding") converted a would-be double-vehicle into one passive watch process.

Post-resolution verification (all direct, this session):
- four-way shasum agreement: CI pack `cec93f30866b2e4f871d06344f63585a0ce1261e` == direct
  tarball download == `npm view` == tencent mirror; tarball 24 files, package.json 0.8.0,
  plugin marker `// border-opencode-plugin v0.8.0` in published bytes.
- consumer ritual on this machine: drift-watch fired DRIFT rc=1 through the new inspect surface
  (first production use caught its own staleness — dogfood exact), `--purge` cleared 0.7.1
  cache, cache re-warmed via npm install @latest, `border opencode inspect` -> all six aspects
  PASS rc=0 with cache 0.8.0 self-consistent + identity handshake passing on the FRESH published
  dist (content assurance via the gate's own tool).
- npm audit signatures: 444 packages verified registry signatures (border-customs included).
- sentinel retired after FOUND (pkill self-match lesson noted: `pkill -f <script>` from a shell
  whose own cmdline contains the pattern kills the caller first — use bracket class).
NOT done (honest scope): V2 sandbox live await-activation re-verify against 0.8.0 (0.7.1
sandbox recipe is archived; run on demand if the owner wants the V2 stamp refreshed).
Order 9 CLOSED (release line complete).
