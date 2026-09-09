# CHANNEL-CONTRACTS — empirical spike (C1) for the `crates` + `rubygems` push channels

Spike date: 2026-09-05. Sandbox: `/tmp/opencode/spike-c1/` (all commands below run
there; nothing in this spike wrote to any registry, and the repo footprint is this
file). Style contract inherited from `src/engines/ADAPTER-CONTRACT.md`: every
measured row was produced by running the real binary/endpoint on this box;
anything that could not be run without an irreversible upload is labelled
**documentary, not measured**. This document is the constitution for plan
`.omo/plans/border-push-channels.md` todos C3 (`crates`) and C4 (`rubygems`) —
an implementer must be able to code against it without re-deriving anything.

Toolchain versions (measured):

| Tool | Version |
|---|---|
| cargo | `1.93.1 (083ac5135 2025-12-15) (built from a source tarball)` |
| gem (RubyGems) | `3.6.7` |
| ruby | `3.3.8 (2025-04-09 revision b200bad6cd) [x86_64-linux-gnu]` |
| gitleaks | `8.30.1` (`~/.local/bin/gitleaks`) |
| python3 | `3.14.4` |

```bash
cargo --version; gem --version; ruby -v; ~/.local/bin/gitleaks version; python3 --version
```

---

## (a) CARGO PACKAGE DETERMINISM — **PASS: deterministic, byte-identical**

Fixture: `cargo new demo --lib` (name `demo`, version `0.1.0`), plant
`ANCHOR.txt`, `git init && git add -A && git commit` (a clean git tree is a
hard prerequisite of `cargo package`). Then three packaging runs.

| Run | Where | .crate sha256 |
|---|---|---|
| run1 | crate1, CARGO_TARGET_DIR=cargo-target1 | `abeb1291f0266868dd76013c41294ba36d90a64bf74f4d87e5c5c3d292b07b8c` |
| run2 | crate1, SAME target dir, `rm -rf $CT/package` + 2 s gap | `abeb1291…b07b8c` (identical) |
| run3 | **fresh `git clone` into crate2/** (different absolute path, different target dir) | `abeb1291…b07b8c` (identical) |

`cmp` run1 vs run2 vs run3: byte-identical. **Verdict: YES — reproducible
across runs, target dirs, and clones. C3 is NOT gated by nondeterminism.**

Structural reasons (measured, not folklore):

- All tar members carry the **fixed mtime `2006-07-24 09:21`**, never wall-clock:
  `tar -tvzf run1.crate` lists `demo-0.1.0/{.cargo_vcs_info.json,.gitignore,ANCHOR.txt,Cargo.lock,Cargo.toml,Cargo.toml.orig,src/lib.rs}` all at that timestamp.
- Gzip header is deterministic: `xxd -l 10 run1.crate` →
  `1f8b 08 08 0000 0000 02ff` — MTIME field = 0, FEXTRA/FNAME present but FNAME
  is only the package filename (`demo-0.1.0.crate`), no absolute path.
- `demo-0.1.0/.cargo_vcs_info.json` content: `{"git": {"sha1": "6fb0721c0970c6f7f1039633116a2dc7d4cd32d0"}, "path_in_vcs": ""}` —
  **the digest is bound to the HEAD commit sha1** (relative path only, no host path).
- `Cargo.toml` inside the .crate is cargo's *normalized* rewrite (adds `edition`,
  `build=false`, `autolib=false`, …); `Cargo.toml.orig` preserves the original.

Determinism domain (measured — the assert in C3 must live inside it):

| Perturbation | digest changes? | evidence |
|---|---|---|
| repackage same tree, same target dir | NO | run1 == run2 |
| fresh clone, different abs path/target dir | NO | run1 == run3 |
| **new git commit** (ANCHOR.txt content changed, HEAD sha1 changed) | YES | clean-tree repackage → `c33a2f7f265873d6b8e7132b4d9e947c11b2d3ddbb5348c61afcd88fa9544c58` |
| **uncommitted dirty file** (`--allow-dirty`) | YES — working-tree bytes are packaged, not HEAD bytes | appended `// dirty line` to src/lib.rs → `e983194716339f24793bdcbc7e39060668544083a170ed7791c2451f43b43c52`, extracted copy contains the dirty line |

⇒ C3 pre-publish repackage-assert is sound **iff** HEAD and the working tree are
unchanged between stage and publish; the plan's risk "cargo publish repacks
internally" is neutralized: the repack of an unchanged repo state is
byte-identical (h1 below strengthens this).

```bash
cd /tmp/opencode/spike-c1/crate1 && cargo new demo --lib && cd demo
printf 'determinism anchor border-spike-c1 2026-09-05\n' > ANCHOR.txt
git init -q . && git config user.email spike@example.invalid && git config user.name spike
git add -A && git commit -qm "spike fixture v1"
export CARGO_TARGET_DIR=/tmp/opencode/spike-c1/cargo-target1
cargo package --allow-dirty --no-verify && sha256sum "$CARGO_TARGET_DIR/package/demo-0.1.0.crate"
rm -rf "$CARGO_TARGET_DIR/package" && sleep 2
cargo package --allow-dirty --no-verify && sha256sum "$CARGO_TARGET_DIR/package/demo-0.1.0.crate"
git clone -q /tmp/opencode/spike-c1/crate1/demo /tmp/opencode/spike-c1/crate2/demo
(cd /tmp/opencode/spike-c1/crate2/demo && CARGO_TARGET_DIR=/tmp/opencode/spike-c1/cargo-target2 \
  cargo package --allow-dirty --no-verify && sha256sum /tmp/opencode/spike-c1/cargo-target2/package/demo-0.1.0.crate)
tar -tvzf /tmp/opencode/spike-c1/run1.crate   # fixed 2006-07-24 mtimes
```

---

## (b) CRATES.IO API POLARITY — **PASS** (read-only GETs only)

Every row measured with `curl -sS -A 'border-spike-test' -o body -w '%{http_code} %{content_type}' '<url>'`.

| GET | status | content-type | body (public data, verbatim/trimmed) |
|---|---|---|---|
| `/api/v1/crates/serde/1.0.200` | **200** | application/json | top level `{ "version": {…} }` — see field list below |
| `/api/v1/crates/serde/0.0.1` | **404** | application/json | `` {"errors":[{"detail":"crate `serde` does not have a version `0.0.1`"}]} `` |
| `/api/v1/crates/serde/999.999.999` | **404** | application/json | `` {"errors":[{"detail":"crate `serde` does not have a version `999.999.999`"}]} `` |
| `/api/v1/crates/no-such-crate-zzz-qq-42` | **404** | application/json | `` {"errors":[{"detail":"crate `no-such-crate-zzz-qq-42` does not exist"}]} `` |
| `/api/v1/crates/serde` | **200** | application/json | 440 988 B (all 316 versions — use `--compressed`), top level `[crate, versions, keywords, categories]` |

⇒ **The 404 `detail` string discriminates the three probe outcomes in one
endpoint class**: version-absent (`does not have a version`) vs crate-absent
(`does not exist`). Content-type is `application/json` on both 200 and 404.

### Version object (`/api/v1/crates/<name>/<version>` → `.version`) keys

`id, crate, num, dl_path, readme_path, updated_at, created_at, downloads,
features, yanked, yank_message, lib_links, license, links, crate_size,
published_by, audit_actions, checksum, rust_version, has_lib, bin_names,
edition, description, homepage, documentation, repository, trustpub_data, linecounts`

Provenance/payload facts (measured for serde 1.0.200):
- `checksum = ddc6f9cc94d67c0e21aaf7eda3a010fd3af78ebf6e096aa6e2e13c79749cce4f`,
  `crate_size = 77611`.
- **`checksum` == sha256 of the downloadable .crate** (verified: GET
  `/api/v1/crates/serde/1.0.200/download` redirects to
  `https://static.crates.io/crates/serde/serde-1.0.200.crate`, HTTP 200,
  `application/gzip`, 77 611 B, `sha256sum` matches the API field exactly).
  ⇒ C3 `confirmedVia: crates-json` can assert the *published artifact digest*
  equals our staged .crate digest, not just that a version string exists.
- `published_by = {"id":3618,"login":"dtolnay","name":"David Tolnay",
  "avatar":"…","url":"https://github.com/dtolnay","github_username_matches":true,
  "created_at":"2012-07-09T03:55:40Z"}` — **no email field anywhere**.
- `yanked: false`, `license: "MIT OR Apache-2.0"`, `repository`, `homepage`,
  `documentation`, `rust_version: "1.31"`, `edition: "2018"`.

### Crate object (`/api/v1/crates/serde` → `.crate`) keys

`badges, categories, created_at, default_version, description, documentation,
downloads, exact_match, homepage, id, keywords, links, max_stable_version,
max_version, name, newest_version, num_versions, recent_downloads, repository,
trustpub_only, updated_at, versions, yanked`

Provenance signals for a claimed name: `crate.repository`, `crate.homepage`,
`crate.documentation`, `crate.keywords[]`, `crate.categories[]`, plus
per-version `published_by` and `versions[0].audit_actions`.

### Owner endpoints (measured — the plan's guessed path is WRONG)

| GET | status | body |
|---|---|---|
| `/api/v1/crates/serde/owner` | **400** | `{"errors":[{"detail":"Invalid URL: unexpected character 'o' while parsing major version number"}]}` — the singular `/owner` path collides with the `<version>` route segment and is parsed as a version number |
| `/api/v1/crates/serde/owner_users` | **400** | same version-parse error |
| `/api/v1/crates/serde/owners` | **200** | `{"users":[ {"kind":"user","id":3618,"login":"dtolnay","url":"…","name":"David Tolnay","avatar":"…","github_username_matches":true}, {"kind":"team","id":8172? …,"login":"github:serde-rs:publish",…} ]}` — mixed users+teams under one `users` key |
| `/api/v1/crates/serde/owner_user` | **200** | `{"users":[ …kind:"user" only… ]}` |
| `/api/v1/crates/serde/owner_team` | **200** | `{"teams":[{"kind":"team","id":8138,"login":"github:serde-rs:publish","url":"https://github.com/serde-rs","name":"publish","avatar":"…"}]}` |
| `/api/v1/crates/no-such-crate-zzz-qq-42/owner_team` | **404** | `` {"errors":[{"detail":"crate `no-such-crate-zzz-qq-42` does not exist"}]} `` |

⇒ **Use `/owners` (plural) or `/owner_user` + `/owner_team`.** Owner entries
carry `id, login, name, url, avatar, github_username_matches` — **no emails
present** on crates.io owner payloads (contrast rubygems, see (g)).

### User-Agent policy (measured)

| Request UA | status |
|---|---|
| `-A 'border-spike-test'` | 200 |
| `-A 'x'` (any non-library string) | **200** |
| header fully suppressed (`-H 'User-Agent:'`) | **403** application/json |
| `-A ''` (curl sends no UA line at all — verified via `-v`) | **403** application/json |
| curl default UA (`curl/8.x`) | **403** application/json |

403 body (verbatim, `<request-id>` per-call): `{"errors":[{"detail":"We require
that all requests include a `User-Agent` header.  To allow us to determine the
impact your bot has on our service, we ask that your user agent actually
identify your bot, and not just report the HTTP client library you're using. …
Bad: `User-Agent: reqwest/0.9.1`  Better: `User-Agent: my_crawler`  Best:
`User-Agent: my_crawler (my_crawler.com/info)` / `my_crawler (help@my_crawler.com)` …
please email help@crates.io and include the request id …"}]}`

⇒ crates.io heuristically rejects **library-default** UAs (`curl/…`,
`reqwest/…`), not merely missing ones. border must send a self-identifying UA
(e.g. `border/<version> (contact)`); do NOT inherit the HTTP client default.

```bash
UA='border-spike-test'; B=https://crates.io/api/v1/crates
for u in "$B/serde/1.0.200" "$B/serde/0.0.1" "$B/serde/999.999.999" "$B/no-such-crate-zzz-qq-42" "$B/serde/owners" "$B/serde/owner_team"; do
  echo "== $u"; curl -sS -A "$UA" "$u" -w ' [%{http_code} %{content_type}]\n' | head -c 400; echo
done
curl -sS -H 'User-Agent:' -o /dev/null -w '%{http_code}\n' "$B/serde/1.0.200"   # 403
curl -sS -o /dev/null -w '%{http_code}\n' "$B/serde/1.0.200"                    # 403 (curl/ UA)
curl -sSL -A "$UA" -o serde-1.0.200.crate -w '%{http_code} %{content_type}\n' "$B/serde/1.0.200/download"
sha256sum serde-1.0.200.crate   # == .version.checksum from the API
```

---

## (c) .CRATE FORMAT + GITLEAKS NATIVE MISS — **PASS (miss confirmed, shim needed)**

`file demo-0.1.0.crate` →
`gzip compressed data, was "demo-0.1.0.crate", max compression, original size modulo 2^32 9728`
— a **gzip** container; `tar -tzf` works (member root `demo-0.1.0/`). The container
is `tar -xzf demo-0.1.0.crate -C ex`-extractable — exactly the `.tgz` handler shape
already in `src/artifacts/extract.ts` (`tar -xzf <archive> -C <dest>`).

Fixture on top of (a)'s crate: planted `src/secret_plant.rs` with the repo fixture
shape from `test/helpers/fixtures.ts:41` using the pinned literal
`AKIAI4Q3EXAMPL3K7X2Q` + a fresh 40-char random secret
(`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`), committed, packaged
(8 files, sha256 `341267fe42d27c69ac2feccfa15ded11d4af13d36b91e5e2526af6bbc5f5ccd8`),
copied to `scanbox/`.

| gitleaks target | output | exit |
|---|---|---|
| `scanbox/` containing only `demo-0.1.0.crate` | `[]`, log line `scanned ~0 bytes (0) in 5.18ms` / `no leaks found` | **0** |
| `scanbox/ex/` (one `tar -xzf` pass) | **2 findings**: `aws-access-token` (match `AKIAI4Q3EXAMPL3K7X2Q`) + `generic-api-key` (secret `aitf…Bi5d`, entropy 4.703), file `…/demo-0.1.0/src/secret_plant.rs` | **1** |

⇒ `.crate` is a **native miss** (extension-based dispatch — gitleaks scans 0 bytes,
it never opens the file), identical class to the `.tgz` miss documented in
ADAPTER-CONTRACT. Shim required: add `.crate → tar -xzf` to
`NATIVE_MISS_EXTENSIONS`/`extractArchive` in `src/artifacts/extract.ts`.

Reproduce (order matters — scan BEFORE creating `ex/`):

```bash
CFG=/home/lab/workspace/harness/border/assets/gitleaks-defaults-v8.30.1.toml
~/.local/bin/gitleaks dir /tmp/opencode/spike-c1/scanbox --max-archive-depth 2 --no-banner \
  -f json --report-path - --gitleaks-ignore-path /dev/null --config $CFG   # → []
tar -xzf /tmp/opencode/spike-c1/scanbox/demo-0.1.0.crate -C /tmp/opencode/spike-c1/scanbox/ex
~/.local/bin/gitleaks dir /tmp/opencode/spike-c1/scanbox/ex --max-archive-depth 2 --no-banner \
  -f json --report-path - --gitleaks-ignore-path /dev/null --config $CFG   # → 2 findings, exit 1
```

---

## (d) .GEM FORMAT + GITLEAKS MISS + METADATA ROUND-TRIP — **PASS**

Fixture `gem1/`: `demo-gem-spike.gemspec` (name `demo-gem-spike`, version literal
`"0.1.0"`, summary, authors, `s.files = ["lib/demo_gem_spike.rb", "LICENSE.txt"]`),
lib file carrying the planted AWS pair (same literal `AKIAI4Q3EXAMPL3K7X2Q`).

Measured container facts:

- `file demo-gem-spike-0.1.0.gem` → **`POSIX tar archive`** (NOT compressed — outer layer is plain tar).
- `tar -tvf <gem>` members (all mtimes fixed **`1980-01-02 08:00` local = 1980-01-02 00:00 UTC**, uid/gid `wheel/wheel`, mode r--r--r--):
  `metadata.gz`, `data.tar.gz`, `checksums.yaml.gz` — the task's expected
  `data.tar.gz + metadata.gz` plus **`checksums.yaml.gz`** (bonus member).
- `data.tar.gz` = gzip tar holding `spec.files` verbatim (relative paths):
  `tar -tzvf ex/data.tar.gz` → `-rw-rw-r-- wheel/wheel 64 1980-01-02 08:00 LICENSE.txt` + `…143 … lib/demo_gem_spike.rb`.
- With `s.files = []` the built gem's `data.tar.gz` is **empty** — the literal
  `files=[]` gemspec cannot carry the planted secret; the detection leg MUST use
  a gemspec whose `files` includes the secret-bearing path (measured: empty variant
  `tar -tzvf` prints nothing).
- **Output filename comes from `spec.name + "-" + spec.version + ".gem"`, NOT the
  gemspec filename**: `gem build empty-files.gemspec` wrote
  `demo-gem-spike-0.1.0.gem`, overwriting the earlier build. Channel must set/derive
  the expected filename from the *spec*, and must pass `-o` explicitly.
- `checksums.yaml.gz` → YAML: `SHA256:` map of {metadata.gz, data.tar.gz, checksums…} + `SHA512:` map (per-member digests; values measured:
  `metadata.gz: 95f900775d4256241703778a502d12d5b2eeb3b86386a21db2ef7122fa6010ba`,
  `data.tar.gz: dae5536d6035f67546136f12ffe1fc52d602bdffc8dd5eeba120fec2313c4cd7` for the empty variant).
- Gzip headers of the three members: `1f8b 08 00 80f7cf12 02 03` — MTIME = the
  fixed 1980-01-02 constant (0x12cff780), FNAME flag set to short member names,
  no host paths.

**metadata.gz format (measured, resolving the plan's open question): YAML, not Marshal.**
`gzip -dc metadata.gz | head` →
```
--- !ruby/object:Gem::Specification
name: demo-gem-spike
version: !ruby/object:Gem::Version
  version: 0.1.0
platform: r
```
`YAML.load` (safe, with permitted classes / or `YAML.unsafe_load_file`) returns a
`Gem::Specification` instance; `Marshal.load` fails. The tagged-class form means
plain safe_load raises — parse via `Gem::Specification.from_yaml` after
`gzip -dc`, or `YAML.unsafe_load`. Fields include `name, version, platform,
authors, summary, date, files, …` (full spec YAML).

Gitleaks legs (same command shape as (c), `--max-archive-depth 2 --gitleaks-ignore-path /dev/null --config assets/gitleaks-defaults-v8.30.1.toml`):

| target | findings | exit |
|---|---|---|
| dir containing only `d1.gem` | `[]` — `scanned ~0 bytes (0)` → **native miss** (`.gem` unknown extension; outer layer is plain tar) | 0 |
| **outer-only extraction** (`tar -xf d1.gem -C gem-outer/`) | **2 findings**: `aws-access-token` AND `generic-api-key` on path `/tmp/…/gem-outer/data.tar.gz!lib/demo_gem_spike.rb` — **gitleaks natively opens the nested `data.tar.gz` itself** | 1 |
| outer+inner double extraction | findings on both `data/lib/demo_gem_spike.rb` and `data.tar.gz!lib/demo_gem_spike.rb` (same secret, two paths → 2 separate aws-access-token findings; fingerprint is path-scoped, value dedup did NOT collapse them) | 1 |

⇒ **Shim decision (load-bearing for the plan): ONE `tar -xf` pass suffices for
the gitleaks leg** — after outer extraction the nested `data.tar.gz`/`metadata.gz`
are gitleaks-native extensions and `--max-archive-depth 2` descends into them
(native archive paths are reported with the `archive!member` separator). No
double-extraction required for scanning; double extraction is only needed if the
channel wants plain file paths for its own artifact model.

Secret-value trap found while measuring (d): a 32-char planted value containing
dictionary words (`…notarealsecret…`, entropy 4.85) fires **only**
`aws-access-token` — `generic-api-key`'s vendored allowlist/stopwords
(`assets/gitleaks-defaults-v8.30.1.toml:638-665`: `entropy = 3.5`,
regexTarget=match allowlist, ~400-word stopword list incl. `secret`-adjacent
words) silently rejects it. A 40-char random alnum value fires both rules in
every container shape tested. ⇒ Fixture secrets must be `randAwsPair()`-style
random values (which border's helper already produces), never human-readable
placeholders, or the gem/crate detection-leg tests can flake to 1 finding.

```bash
cd /tmp/opencode/spike-c1/gem1
gem build demo-gem-spike.gemspec -o d1.gem
file d1.gem                                  # POSIX tar archive
tar -tvf d1.gem                              # metadata.gz data.tar.gz checksums.yaml.gz @ 1980-01-02
tar -xf d1.gem -C gem-outer/ && tar -tzvf gem-outer/data.tar.gz
gzip -dc gem-outer/metadata.gz | head -4     # --- !ruby/object:Gem::Specification
ruby -ryaml -e 'o=YAML.unsafe_load_file("metadata.yaml"); puts [o.class,o.name,o.version,o.date,o.files].inspect'
CFG=/home/lab/workspace/harness/border/assets/gitleaks-defaults-v8.30.1.toml
~/.local/bin/gitleaks dir /tmp/opencode/spike-c1/gem-scan2 --max-archive-depth 2 --no-banner -f json \
  --report-path - --gitleaks-ignore-path /dev/null --config $CFG          # [] (miss)
~/.local/bin/gitleaks dir /tmp/opencode/spike-c1/gem-outer2 --max-archive-depth 2 --no-banner -f json \
  --report-path - --gitleaks-ignore-path /dev/null --config $CFG          # 2 findings via data.tar.gz!…
```

---

## (e) GEM BUILD DETERMINISM — **PASS: deterministic (plan assumption FALSIFIED)**

| Test | Result |
|---|---|
| `gem build … -o a.gem`; sleep 65; `-o b.gem` | sha256 `9ba24349b956a9090de07c1ecdc7522a16a95b7990cd2e1108e149ae0b17bac6` **identical**, `cmp` byte-identical |
| rebuilt fixture `d1.gem` / sleep 62 / `d2.gem` | `466956467a67f2639c4d36110e70c4e5d9873641caf1eb2e17fe12ea8c4aaa75` identical |
| same source copied to `gem1b/` (different absolute build dir), `-o e1.gem` | `4669564…aaa75` — identical to `d1.gem` |
| per-member diff a vs b | `metadata.gz`, `data.tar.gz`, `checksums.yaml.gz` each byte-identical |

**Why it is deterministic — the plan's C4 premise is WRONG:** the spec `date:`
defaults to the fixed constant **`1980-01-02 00:00:00 UTC`** (measured via
YAML load of metadata.gz), NOT the build timestamp. RubyGems 3.6.7 embeds
`1980-01-02` (and the same epoch in every tar/gzip mtime) unless overridden.

Override matrix (measured):

| Control | `date:` in metadata | gem digest |
|---|---|---|
| default | `1980-01-02 00:00:00 UTC` | deterministic |
| `SOURCE_DATE_EPOCH=1000000000 gem build` | `2001-09-09 00:00:00 Z` | `f4d4705ef41d60e0786496c0e1b85d000035f140e2cb9702f0261714ebc49a22` (changes) |
| gemspec sets `s.date = Time.now` explicitly | wall-clock | **nondeterministic — documentary** (RubyGems honours an explicit `date=`; not exercised here, flag for C4: reject/normalize gemspecs that assign `date`) |

⇒ **Freshness gate for rubygems can use the same repackage-digest assert class as
crates** (plan said key-match because of build date — no longer required), with
the gemspec-`date`-override caveat. Note: unlike cargo, `gem build` does NOT
embed the git HEAD — a new commit does not change the gem digest unless tracked
file *contents* change (and gem build never touches git). Two packaging tools,
two different determinism domains: cargo = f(tree, HEAD sha1), gem = f(tree only).

```bash
cd /tmp/opencode/spike-c1/gem1
gem build demo-gem-spike.gemspec -o a.gem && sleep 65
gem build demo-gem-spike.gemspec -o b.gem && cmp a.gem b.gem && echo IDENTICAL
SOURCE_DATE_EPOCH=1000000000 gem build demo-gem-spike.gemspec -o c.gem
tar -xf c.gem -C exc && gzip -dc exc/metadata.gz | grep -m1 'date:'   # 2001-09-09
```

---

## (f) PUBLISH ARGV SURFACE — **PASS** (no real publish — upload is irreversible)

### cargo publish (measured `cargo publish --help`, cargo 1.93.1)

Relevant flags verbatim: `-n, --dry-run  Perform all checks without uploading`,
`--index <INDEX>  Registry index URL to upload the package to`,
`--registry <REGISTRY>`, `--no-verify  Don't verify the contents by building them`,
`--allow-dirty  Allow dirty working directories to be packaged`,
`--target-dir <DIRECTORY>`, `--manifest-path <PATH>`, `--offline`, `--frozen`.
There is **no** `--token` CLI flag in this cargo (auth is via
`$CARGO_HOME/credentials.toml` / `CARGO_REGISTRY_TOKEN`) — documentary from help
text absence + cargo docs.

### cargo publish --dry-run WITHOUT credentials (measured, decisive)

Setup: `CARGO_HOME=/tmp/opencode/spike-c1/cargohome` (fresh, no
credentials.toml; box also has no `~/.cargo/credentials.toml`), demo crate from
(a)+(c). Command `cargo publish --dry-run --allow-dirty --no-verify`:

- **exit code 0**, stdout empty; stderr verbatim sequence:
  `Updating crates.io index` → `warning: manifest has no description, license, license-file, documentation, homepage or repository | = note: see https://doc.rust-lang.org/cargo/reference/manifest.html#package-metadata …` →
  `Packaging demo v0.1.0 (/tmp/…/crate1/demo)` → `Packaged 8 files, 1.4KiB (1.1KiB compressed)` →
  `Uploading demo v0.1.0 (/tmp/…/crate1/demo)` → `warning: aborting upload due to dry run`.
- It DOES contact the registry: sparse index fetched — cache files created at
  `$CARGO_HOME/registry/index/index.crates.io-1949cf8c6b5b557f/.cache/de/mo/demo`
  + `config.json`.
- It does NOT fail without a token — it stops before upload ("aborting upload
  due to dry run").
- **CRITICAL negative result:** dry-run performs **no name/version collision
  check** even when the exact version is already published: a locally-authored
  crate named `serde` version `1.0.200` (a taken name AND taken version) also
  exits 0 with `warning: aborting upload due to dry run`. The 409/existence
  error only happens on a real upload PUT. ⇒ **border's probe leg (b) is the
  only collision detector; `--dry-run` merely validates local packaging + index
  reachability and is SAFE to wire into the channel's dry-run leg** (read-only
  network, no credentials needed, no upload possible).

### gem push (measured `gem push --help`, rubygems 3.6.7)

Usage `gem push GEM [options]`; options verbatim:
`-k, --key KEYNAME  Use the given API key from /home/lab/.local/share/gem/credentials`,
`--otp CODE  Digit code for multifactor authentication` (env `GEM_HOST_OTP_CODE`),
`--host HOST  Push to another gemcutter-compatible host (e.g. https://rubygems.org)`,
`--attestation FILE  Push with sigstore attestations`, `-p, --[no-]http-proxy [URL]`,
common opts (`--config-file FILE`, `--backtrace`, `--norc`…). Help text states:
push uploads to the default `https://rubygems.org` and reads auth from
`~/.gem/credentials` or env `GEM_HOST_API_KEY`.

Credential-failure / success message shapes — **documentary, not measured**
(exercising them requires a real PUT, gate-forbidden): per the `gem push --help`
description above and RubyGems publishing guide
(<https://guides.rubygems.org/publishing/>), success prints
`Pushed gem: <name>-<version>`; a missing/invalid key yields
`Access was denied for performing this action, could not find credentials in …`
/ HTTP 401/403 `You have already taken the … name` class messages on collisions;
MFA-enabled accounts require `--otp`. C4 must treat gem push stderr patterns as
**unverified until a staging host exists** and must not auto-retry on auth-class
errors. `--host` expects a base URL of a gemcutter-compatible API host (rubygems
docs: <https://guides.rubygems.org/using-the-site/> / `gem push --help` above).

```bash
cargo publish --help | sed -n '1,20p'
gem push --help
cd /tmp/opencode/spike-c1/crate1/demo
CARGO_HOME=/tmp/opencode/spike-c1/cargohome CARGO_TARGET_DIR=/tmp/opencode/spike-c1/cargo-target1 \
  cargo publish --dry-run --allow-dirty --no-verify; echo "exit=$?"
```

---

## (g) RATE LIMIT / POLICY PROBE — **PASS: no throttling observed at ×6**

| Probe (identical UA `border-spike-test`, sequential, no delay) | Result |
|---|---|
| 6 × GET `https://crates.io/api/v1/crates/serde` (`--compressed`) | **all 200** (49 033 B compressed); per-request time 17.65 / 4.14 / 1.48 / 1.58 / 1.09 / 2.25 s |
| 6 × GET `https://rubygems.org/api/v1/gems/rake.json` | **all 200** `application/json; charset=utf-8`; times 3.70 / 3.05 / 1.63 / 1.15 / 2.46 / 17.01 s |
| GET `https://rubygems.org/api/v1/gems/rake.json` with NO UA | **200** (rubygems has no crates.io-style UA gate — but border should still send its UA as good practice) |

No 403, no 429 anywhere at ×6 burst ⇒ probe policy: sequential GETs at human
burst scale are fine; the crates.io **UA requirement** (b) is the only hard
request precondition. High-variance latency (up to 17.6 s) ⇒ channel HTTP
timeout budget must be ≥ ~30 s per probe request.

RubyGems endpoint polarity matrix (all measured):

| GET | status | content-type | body |
|---|---|---|---|
| `/api/v2/rubygems/rake/versions/13.0.6.json` | **200** | application/json; charset=utf-8 | full version JSON (keys: `name, number, version, platform, ruby_version, rubygems_version, prerelease, downloads, downloads_count, created_at, released?, built_at, summary, description, authors, info, licenses, metadata, sha, spec_sha, dependencies, requirements, yanked, gem_uri, project_uri, homepage_uri, source_code_uri, …`) |
| `/api/v2/rubygems/rake/versions/999.999.999.json` (gem exists, version doesn't) | **404** | **text/plain; charset=utf-8** | `This version could not be found.` |
| `/api/v2/rubygems/no-such-gem-zzz-42/versions/1.0.0.json` (gem absent) | **404** | text/plain; charset=utf-8 | `This gem could not be found` ← **no trailing period, distinct message** |
| `/api/v1/gems/rake.json` | 200 | application/json | gem JSON, keys: `name, version, platform, ruby_abi, authors, info, description?, licenses, metadata{changelog_uri,bug_tracker_uri,source_code_uri,documentation_uri}, yanked, sha, spec_sha, dependencies, downloads, version_downloads, created_at?, version_created_at, gem_uri, project_uri, homepage_uri, source_code_uri, documentation_uri, mailing_list_uri, bug_tracker_uri, funding_uri, wiki_uri, changelog_uri` — **no `email`, no `uri`, no `owners` key in the v1 gems.json payload** |
| `/api/v1/gems/no-such-gem-zzz-42.json` | **404** | text/plain; charset=utf-8 | `This rubygem could not be found.` |
| `/api/v1/gems/rubygems-release.json` (suggested in task) | **404** — that gem no longer exists; use `rake`/`bundler` as probe fixtures | | |
| `/api/v1/gems/<name>/owners.json` | **200** for existing gems | application/json | array of `{"id":117,"handle":"jimweirich","role":"owner"}` — **`email` present for some owners** (e.g. `hsbt` → `hsbt@ruby-lang.org`), fields optional per entry |
| `/api/v1/gems/no-such-gem-zzz-42/owners.json` | 404 | text/plain | `This rubygem could not be found.` |

⇒ **(h4) version-probe and name-probe CAN share one call**: `GET
/api/v2/rubygems/<name>/versions/<v>.json` returns three distinguishable 404
text bodies (version-missing vs gem-missing), so one request resolves both
channel decisions. Provenance signals for a claimed rubygems name:
`authors` (free string), `metadata` hash, `homepage_uri`, `source_code_uri`,
`project_uri`, `documentation_uri`, `changelog_uri`, `bug_tracker_uri`,
`funding_uri`, `wiki_uri`, plus `owners.json` handles/emails. Note
`sha`/`spec_sha` = artifact/spec digests (rubygems analogue of crates.io
`checksum`).

```bash
UA='border-spike-test'
for i in 1 2 3 4 5 6; do curl -sS --compressed -A "$UA" -o /dev/null -w '%{http_code} %{time_total}s\n' https://crates.io/api/v1/crates/serde; done
for i in 1 2 3 4 5 6; do curl -sS -A "$UA" -o /dev/null -w '%{http_code} %{time_total}s\n' https://rubygems.org/api/v1/gems/rake.json; done
for u in 'v2/rubygems/rake/versions/13.0.6.json' 'v2/rubygems/rake/versions/999.999.999.json' \
         'v2/rubygems/no-such-gem-zzz-42/versions/1.0.0.json' 'v1/gems/no-such-gem-zzz-42.json' \
         'v1/gems/bundler/owners.json'; do
  echo "== $u"; curl -sS -A "$UA" -w ' [%{http_code} %{content_type}]\n' "https://rubygems.org/api/$u" | head -c 300; echo; done
curl -sS https://rubygems.org/api/v1/gems/rake.json -o /dev/null -w 'no-UA: %{http_code}\n'
```

---

## (h) EXTRA DECISIONS — all MEASURED

1. **`--no-verify` vs full package:** byte-identical .crate digests. Full
   `cargo package --allow-dirty` (runs `Verifying` + a dev-profile build of the
   unpacked crate) and `cargo package --allow-dirty --no-verify` on the same repo
   state both produced `c33a2f7f265873d6b8e7132b4d9e947c11b2d3ddbb5348c61afcd88fa9544c58`.
   ⇒ `--no-verify` only skips the *build-and-check* step; it changes nothing about
   the artifact bytes. C3's `--no-verify` choice is safe for digest-assert.
2. **Absolute paths / host timestamps in the .crate:** none — cross-clone
   (different abs path + different CARGO_TARGET_DIR) and cross-directory gem
   builds are byte-identical; mtimes are fixed constants (2006-07-24 for cargo,
   1980-01-02 for gem), gzip MTIME 0 for cargo members' container. Caveat: the
   digest is *not machine-stable across git HEAD changes* (`.cargo_vcs_info.json`
   embeds HEAD sha1) and *not tree-dirty-stable* (`--allow-dirty` packages the
   working tree) — the (a) domain table defines the assert boundary.
3. **crates.io version-absent body:** 404, `application/json`,
   `` {"errors":[{"detail":"crate `serde` does not have a version `X`"}]} `` — same
   shape class as every other crates.io error (`errors[].detail`).
4. **rubygems v2 endpoint, gem-exists/version-absent vs gem-absent:** DIFFERENT
   404 text bodies (`This version could not be found.` vs
   `This gem could not be found`) ⇒ probes shareable, see (g).

---

## Design implications (C3/C4 constitution)

**Determinism verdicts:** `cargo package` — **deterministic**, digest =
f(working-tree content, HEAD sha1); repackage-assert valid. `gem build` —
**deterministic** (fixed 1980-01-02 date; NOT build-clock, plan premise
overturned); freshness gate may use repackage-digest for both channels; reject
gemspecs assigning `s.date` (documentary caveat) and mind that gem digest is
blind to git HEAD.

**Required request headers:** crates.io — self-identifying `User-Agent`
mandatory (missing/empty/library-default ⇒ 403 JSON; any custom string ⇒ 200);
recommend `--compressed` (uncompressed `/crates/serde` ≈ 441 KB). rubygems —
none required (no-UA ⇒ 200); send UA anyway. Timeout budget ≥ 30 s (observed
17.6 s tail).

**Status/body classification table (measured):**

| Condition | crates.io | rubygems v1 `gems/<n>.json` | rubygems v2 `…/versions/<v>.json` |
|---|---|---|---|
| name present, version present | 200 `{version:{…}}` | 200 gem JSON | 200 version JSON |
| name present, version absent | 404 JSON `` {"errors":[{"detail":"crate `X` does not have a version `V`"}]} `` | — | 404 text `This version could not be found.` |
| name absent (available) | 404 JSON `` {"errors":[{"detail":"crate `X` does not exist"}]} `` | 404 text `This rubygem could not be found.` | 404 text `This gem could not be found` (no dot) |
| UA policy violation | 403 JSON `errors[0].detail` (UA sermon) | n/a (no gate) | n/a |
| malformed version segment | 400 JSON `Invalid URL: unexpected character 'o' while parsing major version number` | n/a | n/a |
| 429 | **never observed** (×6 burst) | never observed | never observed |

**Shim argv per format** (feeds `src/artifacts/extract.ts` — mirror the `.tgz`
handler):

| format | container | shim extraction argv | gitleaks leg |
|---|---|---|---|
| `.crate` | gzip tar, root `name-version/` | `tar -xzf <f>.crate -C <dest>` | full scan of `<dest>`; native miss on raw file (0 bytes scanned) |
| `.gem` | plain tar → `metadata.gz`,`data.tar.gz`,`checksums.yaml.gz` | `tar -xf <f>.gem -C <dest>` (**one pass**) | scan `<dest>` directly — `--max-archive-depth 2` already descends into `data.tar.gz` (report paths arrive as `dir/data.tar.gz!lib/x.rb`) |

**Cargo `--dry-run` wiring:** SAFE for the channel dry-run leg (read-only: index
GET + local packaging, aborts before upload, exit 0, no token required) but it
**detects nothing about name/version occupancy** — collision detection lives
exclusively in the (b)/(g) GET probes; keep probe leg and dry-run leg separate.
**Confirmed-stage backstop:** after publish, GET `…/crates/<name>/<version>` and
compare `version.checksum` against the staged `.crate` sha256 (equality proven
against a real registry artifact in (b)).

**Fixture traps pinned by this spike:** reuse literal `AKIAI4Q3EXAMPL3K7X2Q`
with a *random* 40-char companion secret (dictionary-word secrets get
`generic-api-key` stopword-allowlisted → silent 1-finding flake, (d)); `gem
build` output name derives from the spec, not the gemspec filename — pass `-o`;
`s.files=[]` ships an empty `data.tar.gz` — the gemspec must list the secret
file; scan `.crate`/`.gem` **before** creating the extraction dir in the same
folder; cargo's owners route is `/owners` (plural) — `/owner` 400s as a version
parse error.

