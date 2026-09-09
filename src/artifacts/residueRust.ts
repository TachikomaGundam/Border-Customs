// provenance: R3a crates leg (plan border-residue-gate §57) + VERIFIER-REPORT-R3A.json fix round
// (blocker R3A-V1, nit N1) + VERIFIER-REPORT-R3A-FIX.json round (blocker R3AFIX-F1 env-shape,
// nits N-a/N-b). Doctrine: NO T1 pass-lane for cargo either — build.rs is unmatchable
// ⇒ UNKNOWN ⇒ the pre-R3a CRITICAL default stays, so this leg only ADDS detection (plan Must-NOT:
// never softer). Cargo runs build.rs on every consumer build ⇒ its writes are install-time surface:
// plan §57 names exactly the {fs::write, File::create} verb pair and confines targets to
// OUT_DIR / CARGO_TARGET_TMPDIR (cargo's discarding roots; R1 anatomy). Widening the verb set is a
// PLAN amendment, not a matcher edit (contract §8). Cargo.toml network scan is scoped to
// [..build-dependencies] section bodies only — runtime [dependencies] is T0 negative space (plan §56).
import {
  RESIDUE_T3_RULE,
  RS_BUILD_DEPS_SECTION,
  RS_BUILD_HOOK_BASENAMES,
  RS_CONFINEMENT_ENV_TOKENS,
  RS_WRITE_CALL,
} from "../rules/residueMatchers.ts";
import { FAMILY_WORDING, familyHits, firstArgument, readText, sectionBlock, t4HitFor, type ResidueHit } from "./residue.ts";

/** Residue hits for one extracted crate (pkgDir + inner rels incl. the `<name>-<version>/` wrapper). */
export function residueCratesHits(pkgDir: string, innerRels: readonly string[]): ResidueHit[] {
  const hits: ResidueHit[] = [];
  for (const rel of innerRels) {
    const text = readText(pkgDir, rel);
    if (text === null) continue;
    const name = rel.split("/").pop() ?? "";
    if (RS_BUILD_HOOK_BASENAMES.includes(name)) {
      hits.push(...familyHits(rel, text, FAMILY_WORDING.crates));
      for (const m of text.matchAll(RS_WRITE_CALL)) {
        const arg = firstArgument(text, (m.index ?? 0) + m[0].length - 1);
        // fail CLOSED on an unparseable argument (truncated call ⇒ row, never silence — R3a-F).
        if (arg === null || !confined(text, arg)) {
          hits.push({
            rule: RESIDUE_T3_RULE,
            severity: "HIGH",
            message: `build-script code in '${rel}' writes outside the OUT_DIR/CARGO_TARGET_TMPDIR confinement roots: ${JSON.stringify((arg ?? m[0]).trim().replace(/\s+/g, " ").slice(0, 120))} (T3) — cargo discards those roots; anything else is residue (plan §57)`,
            fileRel: rel,
            patternId: RS_CONFINEMENT_PATTERN_ID,
          });
        }
      }
    }
    if (name === "Cargo.toml") {
      const buildDeps = sectionBlock(text, RS_BUILD_DEPS_SECTION);
      hits.push(...familyHits(rel, buildDeps, FAMILY_WORDING.crates));
    }
    const t4 = t4HitFor(rel, text);
    if (t4 !== null) hits.push(t4);
  }
  return hits;
}

// ------------------------------------------- §57 write-confinement (V1/N1 fix round)

/** R3A-N2 discriminator: confinement shares (rule, file) with the family lanes on dotfile writes,
 *  so its rows carry a stable digest suffix; the family lanes stay key-identical to 0.2.0. */
const RS_CONFINEMENT_PATTERN_ID = "rs-confinement";
//
// A write target is CONFINED iff it makes a LIVE env-reference call — `env::var("OUT_DIR")` or
// `env::var("CARGO_TARGET_TMPDIR")`, optional `std::` prefix (R3AFIX-F1: OUT_DIR/CARGO_TARGET_TMPDIR
// are legitimately reachable in Rust ONLY through env::var-family calls, so recognition is confined
// to that form; the prior substring test accepted path text like "/usr/local/bin/OUT_DIR" fail-OPEN),
// or its chain HEAD is one identifier whose EVERY recorded assignment — `let [mut] id = rhs` and bare
// `id = rhs` alike (VERIFIER-REPORT-R3A R3A-V1: a let-only scan let `o = format!(HOME…)` rebinds score
// zero) — makes such a call itself, or resolves through the same map to another fully-confined
// identifier. The ALL rule re-applies at every hop and cycles fail closed, so one rebind anywhere
// voids the route. Anything the closed grammar cannot decide (unknown head, unbound id — a tuple
// destructure `let (o, _) = …` records no plain `o =` assignment, N-b — zero assignments, self-refining
// `let o = f(&o)` chains, multi-line fluent chains, exotic indirection like `env!("OUT_DIR")` or a
// const alias) ⇒ violation: false alarms are recoverable, silent escapes are not. INVISIBLE (no row,
// escape class governed by contract §8): in-place mutation of a confined id without assignment —
// `o.push_str(..)` and `o += ".."` alike (N-a: `+=` is NOT caught by ASSIGN_SHAPE, the `+` breaks the
// `\w+\s*=` adjacency; it never was a violation row).

/** Code-position `env::var("<root>")` test — the ONLY accepted confinement shape (R3AFIX-F1).
 *  `"` strings, `r#"…"#` raw strings and line comments are skipped; block comments are consumed at
 *  their TRUE extent — Rust nests them (Rust Reference: two `/*` openers need two closers, so the
 *  inner one does NOT end the comment), so the skip tracks depth (R3AFIX3-B1: a flat
 *  `indexOf(closer)` ended early on nested openers and resurrected a
 *  commented-out env::var as live code ⇒ token-in-comment confined, fail-OPEN). Quotes inside comments
 *  are inert (the depth loop owns the region); unterminated regions consume the rest of the slice, and
 *  char-literal apostrophes only ever shift string windows: every mis-parse hides text and can only
 *  LOSE a real call ⇒ missed confinement ⇒ violation row, never acceptance (fail closed). */
function envRefCall(s: string): boolean {
  let i = 0;
  while (i < s.length) {
    const ch = s.charAt(i);
    if (ch === "/" && s.charAt(i + 1) === "/") {
      const nl = s.indexOf("\n", i);
      i = nl === -1 ? s.length : nl;
      continue;
    }
    if (ch === "/" && s.charAt(i + 1) === "*") {
      let depth = 1;
      let j = i + 2;
      while (j < s.length && depth > 0) {
        if (s.charAt(j) === "/" && s.charAt(j + 1) === "*") {
          depth += 1;
          j += 2;
        } else if (s.charAt(j) === "*" && s.charAt(j + 1) === "/") {
          depth -= 1;
          j += 2;
        } else {
          j += 1;
        }
      }
      i = j;
      continue;
    }
    if (ch === '"') {
      const close = endQuoted(s, i);
      i = close < 0 ? s.length : close + 1;
      continue;
    }
    const prevWord = i > 0 && /\w/.test(s.charAt(i - 1));
    if (!prevWord) {
      const raw = /^r(#*)"/.exec(s.slice(i));
      if (raw !== null) {
        const term = `"${raw[1] ?? ""}`;
        const end = s.indexOf(term, i + raw[0].length);
        i = end === -1 ? s.length : end + term.length;
        continue;
      }
      const head = ENV_REF_HEAD.exec(s.slice(i));
      if (head !== null) {
        const open = i + head[0].length - 1;
        const close = endQuoted(s, open);
        if (close < 0) return false;
        if (RS_CONFINEMENT_ENV_TOKENS.includes(s.slice(open + 1, close))) return true;
        i = close + 1;
        continue;
      }
    }
    i += 1;
  }
  return false;
}
const ENV_REF_HEAD = /^(?:std::)?env::var\s*\(\s*"/;
/** Index of the closing quote of the `"`-string opened at `open` (backslash escapes honored), -1 if
 *  unterminated. `firstArgument` uses the same escape rule, so both agree on what a string is. */
function endQuoted(s: string, open: number): number {
  for (let i = open + 1; i < s.length; i += 1) {
    const ch = s.charAt(i);
    if (ch === "\\") i += 1;
    else if (ch === '"') return i;
  }
  return -1;
}
/** identifier = rhs, non-comparison: `==`, `!=`, `<=`, `>=`, `=>` and compound ops can never match
 *  (\w+ sits immediately before optional whitespace before `=`); strings/comments match like NB2
 *  prose (§1.6-9): over-matching only ever adds rows, fail-closed by direction. */
const ASSIGN_SHAPE = /\b(\w+)\s*=(?![=>])/g;
const RAW_ID_HEAD = /^(?:&+\s*)?(?:mut\s+)?([A-Za-z_]\w*)$/;

/** Every textual assignment to tracked identifiers: id → list of rhs slices. Statement end = first
 *  `;` after the `=`; a following assignment starting before that `;` ends the slice early; with no
 *  `;` left, the slice stops at the newline (shortest-slice = fail-closed). Multi-line bindings
 *  (`let o = Path::new(\n "OUT_DIR");`) stay whole because the slice spans newlines. */
function allAssignments(text: string): Map<string, string[]> {
  const map = new Map<string, string[]>();
  const marks = [...text.matchAll(ASSIGN_SHAPE)].map((m) => ({ id: m[1] ?? "", start: m.index ?? 0, len: m[0].length }));
  for (let k = 0; k < marks.length; k += 1) {
    const { id, start, len } = marks[k] as { id: string; start: number; len: number };
    const after = start + len;
    const semi = text.indexOf(";", after);
    const next = k + 1 < marks.length ? (marks[k + 1] as { start: number }).start : Infinity;
    const eol = text.indexOf("\n", after);
    const end = semi === -1 ? Math.min(next, eol === -1 ? text.length : eol) : Math.min(semi, next);
    const bucket = map.get(id) ?? [];
    bucket.push(text.slice(after, end));
    map.set(id, bucket);
  }
  return map;
}

/** Data-flow head of a `.method(..)` / `::assoc(..)` / `macro!(..)` chain: methods recurse into the
 *  receiver, qualified/macro calls into their first argument (N1: PathBuf::from(&out_dir).join(..)
 *  has head out_dir; format!'s first arg is a string literal ⇒ no head). Undecidable shapes
 *  (`+` concatenation, dangling `.`, hop/8 exhausted) ⇒ null ⇒ unresolvable ⇒ violation (fail closed). */
function chainHead(expr: string): string | null {
  let e = expr.trim();
  for (let hop = 0; hop < 8; hop += 1) {
    const bare = RAW_ID_HEAD.exec(e);
    if (bare?.[1] !== undefined) return bare[1];
    if (!e.endsWith(")")) return null;
    const open = matchingOpenParen(e);
    if (open < 0) return null;
    const before = e.slice(0, open).trimEnd();
    if (before.endsWith("!")) {
      const arg = firstArgument(e, open);
      if (arg === null) return null;
      e = arg.trim();
      continue;
    }
    const tail = /(\.|::)(\w+)$/.exec(before);
    if (tail === null) return null;
    if (tail[1] === ".") {
      const recv = before.slice(0, before.length - tail[0].length).trim();
      if (recv === "") return null;
      e = recv;
      continue;
    }
    const arg = firstArgument(e, open);
    if (arg === null) return null;
    e = arg.trim();
  }
  return null;
}

/** Quote-aware backwards paren match for `s[close] === ")"`; escape handling is one-char naive —
 *  mis-parses only ever yield -1 ⇒ chainHead null ⇒ violation, the fail-closed direction. */
function matchingOpenParen(s: string): number {
  let depth = 0;
  let quote: string | null = null;
  for (let i = s.length - 1; i >= 0; i -= 1) {
    const ch = s.charAt(i);
    if (quote !== null) {
      if (ch === quote && s.charAt(i - 1) !== "\\") quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") quote = ch;
    else if (ch === ")") depth += 1;
    else if (ch === "(") {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return -1;
}

function confined(text: string, arg: string): boolean {
  const trimmed = arg.trim();
  if (envRefCall(trimmed)) return true;
  const head = chainHead(trimmed);
  if (head === null) return false;
  return bindingConfined(allAssignments(text), head, new Set([head]));
}

/** V1 core: id is confined iff EVERY recorded assignment (let-shadow OR bare `id =`) names a token
 *  directly or resolves through chainHead to another confined id. The ALL rule re-applies at every
 *  hop, so one poisoned rebind anywhere in the chain voids the whole route. Cycles, unbound ids and
 *  undecidable rhs heads return false — fail-closed by every exit (`visiting` only grows). */
function bindingConfined(assign: Map<string, string[]>, id: string, visiting: Set<string>): boolean {
  const rhss = assign.get(id);
  if (rhss === undefined || rhss.length === 0) return false;
  return rhss.every((rhs) => {
    if (envRefCall(rhs)) return true;
    const next = chainHead(rhs);
    if (next === null || visiting.has(next)) return false;
    visiting.add(next);
    return bindingConfined(assign, next, visiting);
  });
}
