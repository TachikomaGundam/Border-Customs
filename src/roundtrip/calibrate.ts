// provenance: border-inspect-roadmap.md W2.4(a) — G-CALIB pypi lane (target-only diff).
//
// The W2.3 founding pypi run graded 2211 residue rows; 2210 were pip's
// left-behind transitive deps and 1 was a GENUINE orphan dir. The storm drowns
// the signal, so the valve splits ADDED rows by WHO still accounts for them:
// a path claimed by the dist-info/RECORD of a still-installed distribution
// inside the resolved closure is demoted to LOW `residue-roundtrip-dep-owned`
// (non-blocking, owner named); anything else keeps its W2.1 grade untouched.
//
// Fail-closed discipline (plan-mandated, both directions):
//   * closure resolution failure or an unparseable pip report ⇒ EngineRunError
//     ⇒ exit 2 — cannot-verify is never clean;
//   * a path whose attribution is missing, unreadable (RECORD absent), or
//     ambiguous (two dists claim one path) stays BLOCKING — over-report is
//     tolerated, silent-clean is not.
// The scanner only trusts claims INSIDE a site-packages root: RECORD rows that
// escape it (`../../../bin/...`, hostile or buggy wheels) are dropped, so they
// stay HIGH. npm/cargo/gem lanes construct no attribution at all — the pypi
// gate lives in orchestrate.ts, this module stays pure.
import { EngineRunError } from "../engines/support.ts";

export const RT_DEP_RULE = "residue-roundtrip-dep-owned";

/** In-container landing path of the pip resolution report (tmpfs, never scanned: /dev is pruned). */
export const PIP_REPORT_PATH = "/dev/shm/rt-report.json";

/** PEP 503 name canonicalisation — dist-info METADATA and the pip report must be compared through it. */
export function normalizePipName(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, "-");
}

/**
 * pip >=23.1 `install --dry-run --report` v1 JSON ⇒ Map<normalized name, version>.
 * EVERY shape deviation throws: a half-trusted closure would silently widen or
 * narrow demotions, which is exactly the silent-clean failure this valve forbids.
 */
export function parsePipReport(text: string): Map<string, string> {
  const die = (why: string): never => {
    throw new EngineRunError(`roundtrip: pypi closure report unusable (${why}) — cannot verify (fail-closed)`, null);
  };
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    die("not JSON");
  }
  if (typeof doc !== "object" || doc === null) die("not an object");
  const rec = doc as { version?: unknown; install?: unknown };
  // Live pip 25.0.1 emits "version": "1" as a STRING (proven in-container, 2026-09-11);
  // some fixtures/versions use the number 1. Accept both spellings of v1, reject the rest.
  if (String(rec.version) !== "1") die(`report format v${String(rec.version)} is not the v1 surface we validated on pip 25.0.1`);
  if (!Array.isArray(rec.install)) die("install is not an array");
  const closure = new Map<string, string>();
  for (const item of rec.install as unknown[]) {
    const name = (item as { metadata?: { name?: unknown } })?.metadata?.name;
    const version = (item as { metadata?: { version?: unknown } })?.metadata?.version;
    if (typeof name !== "string" || name.length === 0 || typeof version !== "string" || version.length === 0) {
      throw new EngineRunError("roundtrip: pypi closure report unusable (an install entry lacks metadata.name/version) — cannot verify (fail-closed)", null);
    }
    closure.set(normalizePipName(name), version);
  }
  if (closure.size === 0) die("empty install list — a resolvable target must report at least itself");
  return closure;
}

/** Owner lookup table over the m3 claim scan (`owner\tpath` TSV lines). */
export type DepAttribution = {
  readonly exactOwners: ReadonlyMap<string, string>;
  readonly dirOwners: ReadonlyMap<string, string>;
  readonly ambiguous: ReadonlySet<string>;
};

function claim(map: Map<string, string>, ambiguous: Set<string>, path: string, owner: string): void {
  if (ambiguous.has(path)) return;
  const cur = map.get(path);
  if (cur === undefined) map.set(path, owner);
  else if (cur !== owner) {
    map.delete(path);
    ambiguous.add(path);
  }
}

function parentOf(path: string): string {
  const cut = path.lastIndexOf("/");
  return cut <= 0 ? "/" : path.slice(0, cut);
}

/** Adjudication inputs distinguishing a legitimate claimant from a shadow
 *  planted by hostile install code (VERIFIER-REPORT-W24-W4 shadow attack). */
export type ClaimGuard = { readonly pins: ReadonlyMap<string, string>; readonly target: string };

type Claimant = { owner: string; norm: string; ver: string; di: string; root: string; dirName: string; dirVer: string };

/**
 * Build the attribution table. Malformed/relative lines claim nothing (a broken
 * scanner line must never demote); a path claimed under two different owners
 * becomes ambiguous and is dropped from both tables — ownerOf then returns
 * undefined and the row stays blocking.
 *
 * With a guard (the pypi lane), a claim line is honored only if a claimant meta
 * (`@\towner\tnorm\tver\tdi\tdirName\tdirVer`) legitimizes it: the name is NOT
 * the uninstalled target (no self-certification), name+version match a resolver
 * report pin EXACTLY, the dist-info dir canonically encodes that identity in its
 * own name, it is the sole claimant for that name (a shadow beside the real
 * dist-info rejects BOTH — over-report tolerated, laundering not), and the path
 * lives inside the claimant's site-packages root. Without a guard the claim
 * lines parse exactly as before (byte-compatible legacy mode).
 */
export function buildAttribution(claimText: string, guard?: ClaimGuard): DepAttribution {
  const exactOwners = new Map<string, string>();
  const dirOwners = new Map<string, string>();
  const ambiguous = new Set<string>();
  const claimants = new Map<string, Claimant>();
  const normCount = new Map<string, number>();
  const lines = claimText.split("\n");
  if (guard !== undefined) {
    for (const line of lines) {
      if (!line.startsWith("@\t")) continue;
      const f = line.slice(2).split("\t");
      if (f.length !== 6) continue;
      const [owner, norm, ver, di] = f as [string, string, string, string];
      normCount.set(norm, (normCount.get(norm) ?? 0) + 1);
      if (!claimants.has(owner)) claimants.set(owner, { owner, norm, ver, di, root: parentOf(di), dirName: f[4] as string, dirVer: f[5] as string });
    }
  }
  const legit = (owner: string): Claimant | undefined => {
    if (guard === undefined) return {} as Claimant;
    const c = claimants.get(owner);
    if (c === undefined) return undefined;
    if (c.norm === guard.target) return undefined;
    if (guard.pins.get(c.norm) !== c.ver) return undefined;
    if (c.dirName !== c.norm || c.dirVer !== c.ver) return undefined;
    if ((normCount.get(c.norm) ?? 0) !== 1) return undefined;
    return c;
  };
  for (const line of lines) {
    if (line.trim().length === 0 || line.startsWith("@\t")) continue;
    const tab = line.indexOf("\t");
    if (tab <= 0 || line.indexOf("\t", tab + 1) !== -1) continue;
    const owner = line.slice(0, tab);
    const path = line.slice(tab + 1);
    if (!path.startsWith("/") || path.length === 1) continue;
    if (guard !== undefined) {
      const c = legit(owner);
      if (c === undefined || (c as Claimant).root === undefined || !path.startsWith(`${(c as Claimant).root}/`)) continue;
    }
    claim(exactOwners, ambiguous, path, owner);
    for (let dir = parentOf(path); dir.length > 1; dir = parentOf(dir)) {
      claim(dirOwners, ambiguous, dir, owner);
    }
  }
  return { exactOwners, dirOwners, ambiguous };
}

type ClaimableEntry = { readonly kind: "F" | "L" | "D"; readonly path: string };

/** Owning dep of a surviving path, or undefined (= keep today's grade). */
export function ownerOf(entry: ClaimableEntry, attribution: DepAttribution): string | undefined {
  const exact = attribution.exactOwners.get(entry.path);
  if (exact !== undefined) return exact;
  return entry.kind === "D" ? attribution.dirOwners.get(entry.path) : undefined;
}

// Python stdlib only (the image ships python3 by definition of the lane).
// Reads each *.dist-info's METADATA; a closure member's dump is one claimant
// meta line (`@\towner\tnorm\tver\tdi\tdirName\tdirVer` — the raw evidence;
// legitimacy is adjudicated TS-side in buildAttribution, never here) followed
// by its claim lines: the dist-info subtree (always — pip wrote it) plus its
// RECORD file list when the RECORD exists and parses
// (test-d: RECORD missing ⇒ package files unclaimed).
export const CLAIM_SCANNER_PY = [
  "import csv, json, os, re, site, sys",
  "try:",
  "    closure = json.loads(os.environ['BORDER_CLOSURE'])",
  "    assert isinstance(closure, dict) and closure",
  "except Exception:",
  "    sys.exit(4)",
  "def norm(n):",
  "    return re.sub(r'[-_.]+', '-', n).lower()",
  "def read_meta(di):",
  "    name = ''",
  "    ver = ''",
  "    try:",
  "        f = open(os.path.join(di, 'METADATA'), encoding='utf-8', errors='replace')",
  "    except OSError:",
  "        return None",
  "    with f:",
  "        for raw in f:",
  "            line = raw.rstrip('\\n')",
  "            if line == '':",
  "                break",
  "            if not name and line.startswith('Name:'):",
  "                name = line[5:].strip()",
  "            elif not ver and line.startswith('Version:'):",
  "                ver = line[8:].strip()",
  "    return (name, ver) if name and ver else None",
  "roots = []",
  "try:",
  "    roots.extend(site.getsitepackages())",
  "except Exception:",
  "    pass",
  "out = []",
  "seen = set()",
  "for root in roots:",
  "    if not os.path.isdir(root) or root in seen:",
  "        continue",
  "    seen.add(root)",
  "    for d in sorted(os.listdir(root)):",
  "        if not d.endswith('.dist-info'):",
  "            continue",
  "        di = os.path.join(root, d)",
  "        meta = read_meta(di)",
  "        if meta is None or norm(meta[0]) not in closure:",
  "            continue",
  "        owner = meta[0] + '==' + meta[1]",
  "        core = d[:-10]",
  "        cut = core.rfind('-')",
  "        dn = norm(core[:cut]) if cut > 0 else ''",
  "        dv = core[cut + 1:] if cut > 0 else ''",
  "        out.append('@\\t' + owner + '\\t' + norm(meta[0]) + '\\t' + meta[1] + '\\t' + di + '\\t' + dn + '\\t' + dv)",
  "        out.append(owner + '\\t' + di)",
  "        for base, _dirs, files in os.walk(di):",
  "            for fn in sorted(files):",
  "                out.append(owner + '\\t' + os.path.join(base, fn))",
  "        try:",
  "            rf = open(os.path.join(di, 'RECORD'), newline='', encoding='utf-8', errors='replace')",
  "            with rf:",
  "                for row in csv.reader(rf):",
  "                    if not row or not row[0].strip():",
  "                        continue",
  "                    p = os.path.normpath(os.path.join(root, row[0].strip()))",
  "                    if p.startswith(root + os.sep):",
  "                        out.append(owner + '\\t' + p)",
  "        except Exception:",
  "            pass",
  "sys.stdout.write(''.join(x + '\\n' for x in out))",
].join("\n");
