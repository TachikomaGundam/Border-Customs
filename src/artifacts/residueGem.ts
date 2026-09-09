// provenance: .omo/plans/border-residue-gate.md R3b (rubygems leg) — extconf.rb/gemspec-extensions
// scan + T4 artifact-wide pass over .gem data; semantics frozen by src/artifacts/RESIDUE-CONTRACT.md
// §8 R3b amendment. Structural template: residueRust.ts (dedicated per-family leg; unparseable ⇒
// violation; closed tables live ONLY in ../rules/residueMatchers.ts). Container bytes (metadata.gz /
// data.tar.gz layout, extensions YAML shape) measured with gem 3.6.7, probe 2026-09-09; the caller
// (src/artifacts/rubygems.ts) unpacks with the existing extract shim and feeds this pure scanner.
import { basename } from "node:path";

import {
  GEM_ABSOLUTE_LITERAL,
  GEM_ASSIGNMENT,
  GEM_BARE_IDENTIFIER,
  GEM_CHDIR_CALL,
  GEM_EXTENSIONS_KEYS,
  GEM_EXTCONF_BASENAME,
  GEM_HOOK_CALL,
  GEM_OUT_OF_TREE_MARKS,
  GEM_PERCENT_LITERAL,
  GEM_PERCENT_PAIRS,
  GEM_PERSISTENCE_BASENAMES,
  GEM_ROOTED_SLASH_ARG,
  GEM_WRITE_CALL,
  GEM_YAML_COMMENT,
  GEM_YAML_KEY_TERM,
  GEM_YAML_SEQ_ITEM,
  RESIDUE_GEM_UNMATCHED_EXT_RULE,
  RESIDUE_T4_RULE,
  RESIDUE_T3_RULE,
} from "../rules/residueMatchers.ts";
import { type FamilyWording, type ResidueHit, evidenceLine, familyHits, readText, t4HitFor } from "./residue.ts";

/** familyHits wording for the gem lane (contract §8 "Message wording parameterization"). */
export const GEM_WORDING: FamilyWording = { what: "gem install-time", ledger: "gem" };

/** One T4 row per file for the auto-load / hook-registration lanes (plan R3b (b)): the plugin
 *  basename outranks the token lane when a file is both (they would double up on one (rule,file)). */
function gemPersistenceHit(rel: string, text: string): ResidueHit | null {
  if (GEM_PERSISTENCE_BASENAMES.includes(basename(rel))) {
    return {
      rule: RESIDUE_T4_RULE,
      severity: "CRITICAL",
      message: `packed file '${rel}' is a RubyGems plugin: rubygems_plugin.rb is auto-loaded by EVERY later gem/ruby process after install — persistence outlives the install session, the worst shape in the ledger family (T4)`,
      fileRel: rel,
      patternId: "gem-autoload-plugin",
    };
  }
  if (GEM_HOOK_CALL.test(text)) {
    return {
      rule: RESIDUE_T4_RULE,
      severity: "CRITICAL",
      message: `packed file '${rel}' registers Gem installer hooks: "${evidenceLine(text, GEM_HOOK_CALL)}" — the callback runs on every future install/uninstall in this rubygems process (T4)`,
      fileRel: rel,
      patternId: "gem-hook-token",
    };
  }
  return null;
}

/** Slice the write/exec argument span after a GEM_WRITE_CALL match: `(`-opening calls read the WHOLE
 *  argument list (BLK-5 parity: `FileUtils.cp(src, "/usr/local/bin/dst")` escapes through its
 *  destination operand, so confinement judges every argument, not just the first); a call whose verb
 *  match ends in a non-word, non-space delimiter (bare `system "cmd"`, a backtick, or any BLK-6 %x
 *  opener) scans to that delimiter's closer — paired for ( [ { <, the char itself otherwise,
 *  mirroring GEM_PERCENT_PAIRS; a bare verb + `%` operand (BLK-R3bF4-B: `system %q{…}`, `exec %w[…]`)
 *  skips its designator letters, resolves the closer through the same pair table and returns the
 *  QUOTED PAYLOAD only (BLK-R3bF5-A: the `%<desig><delim>` prefix must be stripped exactly like the
 *  %x arm's own slice, or a rooted token (`system %x|/usr/…|`) hides behind the delimiter and the
 *  ROOTED `^`-anchor plus the expansion regex both miss it — box ruby 3.3.8 executed all four
 *  `%x|…| %x!…! %x%…% %x@…@` bare-verb payloads live, 0 rows, probe 2026-09-09). For %q/%Q the quoted
 *  payload is byte-identical to what gemExpandPercentLiterals produced from the full literal, so ONE
 *  expansion path judges it; anything else
 *  (paren-less verb + unknown operand) ⇒ null ⇒ fail-closed. */
function gemVerbSpan(text: string, verbEnd: number, verb: string): string | null {
  const last = verb.charAt(verb.length - 1);
  if (last === "(") return gemCallArgs(text, verbEnd - 1);
  if (last === "%" && !verb.startsWith("%")) {
    let i = verbEnd;
    while (i < text.length && /[A-Za-z]/u.test(text.charAt(i))) i += 1;
    const delim = text.charAt(i);
    if (delim === "") return null;
    const closer = GEM_PERCENT_PAIRS[delim] ?? delim;
    for (let j = i + 1; j < text.length; j += 1) {
      if (text.charAt(j) === "\\") j += 1;
      else if (text.charAt(j) === closer) return `"${text.slice(i + 1, j)}"`;
    }
    return null;
  }
  if (/^[^\w\s(]$/u.test(last)) {
    const closer = last === "[" ? "]" : last === "{" ? "}" : last === "<" ? ">" : last;
    for (let i = verbEnd; i < text.length; i += 1) {
      const ch = text.charAt(i);
      if (ch === "\\") i += 1;
      else if (ch === closer) return text.slice(verbEnd, i);
    }
    return null;
  }
  let i = verbEnd;
  while (i < text.length && (text.charAt(i) === " " || text.charAt(i) === "\t")) i += 1;
  return text.charAt(i) === "(" ? gemCallArgs(text, i) : null;
}

/** Full argument text of a call whose `(` sits at `open`: quote-aware scan to the matching close
 *  paren (nested (), [], {} tracked); unbalanced ⇒ null so the caller fails closed (R3b-F shape). */
function gemCallArgs(text: string, open: number): string | null {
  let depth = 0;
  let quote: string | null = null;
  for (let i = open; i < text.length; i += 1) {
    const ch = text.charAt(i);
    if (quote !== null) {
      if (ch === "\\") i += 1;
      else if (ch === quote) quote = null;
    } else if (ch === '"' || ch === "'" || ch === "`") quote = ch;
    else if (ch === "(" || ch === "[" || ch === "{") depth += 1;
    else if (ch === ")" || ch === "]" || ch === "}") {
      depth -= 1;
      if (depth === 0) return text.slice(open + 1, i);
    }
  }
  return null;
}

/** BLK-4b: rewrite `%q{…}` / `%Q(…)` percent literals as quoted strings so the shared mark tests see
 *  their literal text; an unterminated literal is passed through unchanged (other arms still fail
 *  closed on it). Scan is single-level (nested same-delimiter pairs cost a row via null spans). */
function gemExpandPercentLiterals(s: string): string {
  let out = "";
  let i = 0;
  while (i < s.length) {
    const open = GEM_PERCENT_LITERAL.exec(s.slice(i));
    if (open === null || open.index === undefined) {
      out += s.slice(i);
      break;
    }
    out += s.slice(i, i + open.index);
    const delim = open[1] as string;
    const closer = GEM_PERCENT_PAIRS[delim] ?? delim;
    let j = i + open.index + 3;
    while (j < s.length && s.charAt(j) !== closer) {
      if (s.charAt(j) === "\\") j += 1;
      j += 1;
    }
    if (j >= s.length) {
      out += s.slice(i + open.index, j);
      break;
    }
    out += `"${s.slice(i + open.index + 3, j)}"`;
    i = j + 1;
  }
  return out;
}

/** The shared escape predicate: out-of-tree mark (BLK-R3bF2-A: now RegExp, covering the live `Dir::home`
 *  / `ENV::[]` / `ENV::fetch` colon spellings), rooted-quoted literal, or (BLK-4a + BLK-R3bF2-C) a
 *  rooted BARE token after whitespace OR an opening bracket (`%(/usr/…)`, `%w[/usr/…]`) — all judged on
 *  the percent-literal-expanded text. No /g flags on the mark table: .test() must stay stateless. */
const gemSpanEscapes = (span: string): boolean => {
  const eff = gemExpandPercentLiterals(span);
  return GEM_OUT_OF_TREE_MARKS.some((k) => k.test(eff)) || GEM_ABSOLUTE_LITERAL.test(eff) || GEM_ROOTED_SLASH_ARG.test(eff);
};

/** BLK-2 (R3a ALL-bindings doctrine): capture EVERY single-`=` assignment line `id = rhs` in the
 *  extconf (re-assignments keep all variants; `==`/`=~`/`+=` shapes never match the grammar). */
function gemStringBindings(text: string): Map<string, string[]> {
  const map = new Map<string, string[]>();
  for (const line of text.split("\n")) {
    const mm = GEM_ASSIGNMENT.exec(line);
    if (mm === null) continue;
    const id = mm[1] as string;
    const rhs = (mm[2] as string).trim();
    const prev = map.get(id);
    if (prev === undefined) map.set(id, [rhs]);
    else prev.push(rhs);
  }
  return map;
}

/** Reference pattern for a binding id inside rhs texts (BLK-8): plain word-only ids (locals,
 *  CONSTANTS) keep \\b anchors; ids carrying @/$/? sigils escape the metacharacters and anchor with
 *  lookarounds, since `\\b` is undefined at a non-word sigil edge (`\\b@o\\b` never matches). */
const gemRefPattern = (id: string, flags: "u" | "gu"): RegExp => {
  const esc = id.replace(/[.*+?^${}()|[\]\\]/gu, String.raw`\$&`);
  return new RegExp(/^[\w]+$/u.test(id) ? `\\b${esc}\\b` : `(?<![\\w])${esc}(?![\\w])`, flags);
};

/** Resolve an id to the concatenation of its bound texts, substituting other bound ids recursively
 *  (transitive). Cycle, self-reference, or re-entry ⇒ null = unresolvable (caller fail-closes). */
function gemResolveBinding(map: Map<string, string[]>, id: string, seen: ReadonlySet<string>): string | null {
  if (seen.has(id)) return null;
  const rhss = map.get(id);
  if (rhss === undefined) return null;
  const next = new Set(seen);
  next.add(id);
  const selfRef = gemRefPattern(id, "u");
  const parts: string[] = [];
  for (const rhs of rhss) {
    if (selfRef.test(rhs)) return null;
    let out = rhs;
    for (const other of map.keys()) {
      if (other === id) continue;
      if (!gemRefPattern(other, "u").test(out)) continue;
      const nested = gemResolveBinding(map, other, next);
      if (nested === null) return null;
      out = out.replace(gemRefPattern(other, "gu"), nested);
    }
    parts.push(out);
  }
  return parts.join(" ; ");
}

/** Plan R3b (a) + BLK-2/BLK-4/BLK-5/BLK-8 + BLK-R3bF2-A/B/C/D/E: an extconf.rb write/exec span (the
 *  WHOLE argument list, BLK-5) is confinement-legitimate ONLY when the (percent-literal-expanded) text
 *  carries no out-of-tree mark ($HOME, Dir.home/Dir::home, every ENV lookup spelling, `~/`), no rooted
 *  quoted literal and no rooted BARE token after whitespace or an opening bracket. EVERY bare-identifier
 *  fragment — local, @ivar, @@cvar, $global/$0-style builtin, or CONSTANT — resolves through the file's
 *  ALL-bindings map: escaping resolution ⇒ HIGH; a heredoc (`<<`-starting) RHS is never certifiable ⇒
 *  HIGH unconditionally (BLK-R3bF2-E); unresolvable (never bound — @@cvars and special globals are not
 *  LHS-grammar keys) while a rooted literal sits anywhere in the file ⇒ HIGH (fail closed);
 *  relative/in-tree ⇒ confined. Dir.chdir (either separator, BLK-5) anywhere in the file is itself a
 *  confinement break ⇒ one HIGH row. Marks beat everything (R3a F1 doctrine); an unparseable span rows
 *  HIGH. Method-return bindings and `+=` churn still escape — named in §8 Residual limitations. */
function gemConfinementHits(rel: string, text: string): ResidueHit[] {
  const hits: ResidueHit[] = [];
  if (GEM_CHDIR_CALL.test(text)) {
    hits.push({
      rule: RESIDUE_T3_RULE,
      severity: "HIGH",
      message: `gem install-time code in '${rel}' calls Dir.chdir — the extconf CWD moves, so every later relative write follows it out of the build tree: "${evidenceLine(text, GEM_CHDIR_CALL)}" — exotic-operand cost doctrine: any chdir rows, in-tree or not (T3)`,
      fileRel: rel,
      patternId: "gem-confinement",
    });
  }
  const bindings = gemStringBindings(text);
  const rootedLiteralPresent = GEM_ABSOLUTE_LITERAL.test(text);
  for (const m of text.matchAll(GEM_WRITE_CALL)) {
    const verb = m[0] as string;
    const span = gemVerbSpan(text, (m.index ?? 0) + verb.length, verb);
    let escaped = false;
    let evidence = "";
    if (span === null) {
      escaped = true;
      evidence = "unparseable write/exec argument (fail closed)";
    } else if (gemSpanEscapes(span)) {
      escaped = true;
      evidence = `"${span.trim().slice(0, 120)}"`;
    } else {
      for (const frag of span.split(",")) {
        const operand = frag.trim();
        if (!GEM_BARE_IDENTIFIER.test(operand)) continue;
        const operandRhss = bindings.get(operand);
        if (operandRhss?.some((r) => r.startsWith("<<"))) {
          escaped = true;
          evidence = `unresolvable heredoc-bound operand '${operand}' — the <<RHS holds a multi-line value invisible to the line grammar (fail closed)`;
          break;
        }
        const resolved = gemResolveBinding(bindings, operand, new Set());
        if (resolved === null) {
          if (rootedLiteralPresent) {
            escaped = true;
            evidence = `unresolvable bareword operand '${operand}' while a rooted-path literal exists in the same file (fail closed)`;
            break;
          }
        } else if (gemSpanEscapes(resolved)) {
          escaped = true;
          evidence = `${operand} resolves to "${resolved.trim().slice(0, 120)}"`;
          break;
        }
      }
    }
    if (!escaped) continue;
    hits.push({
      rule: RESIDUE_T3_RULE,
      severity: "HIGH",
      message: `gem install-time code in '${rel}' writes outside the extension build tree: ${verb.trim()} ${evidence} — rubygems executes extconf.rb with the unpacked extension dir as CWD; only in-tree/$extout staging is legitimate (T3)`,
      fileRel: rel,
      patternId: "gem-confinement",
    });
  }
  return hits;
}

const normalizeRel = (rel: string): string => rel.replace(/^\.\//u, "");

/** metadata.gz `extensions:` YAML (flow `[]`/`["a"]` or block seq, gem 3.6.7 measured shapes).
 *  Missing key or `[]` ⇒ [] (pure-ruby gem is T0 silent). Block-seq truth (BLK-3): blank AND comment
 *  lines are skipped without terminating collection; the region ends only at the next top-level
 *  mapping key or EOF (blanks/comments/EOF ⇒ YAML null ⇒ legitimately zero declarations). Any other
 *  unrecognized line inside the region THROWS — the caller turns it into an EngineRunError, never a
 *  silent clean (plan R3b AC: declared-but-missing must surface). BLK-7 (VERIFIER-REPORT-R3B-FIX):
 *  the scan counts EVERY top-level `extensions:` occurrence first — psych/rubygems resolve duplicate
 *  keys LAST-wins (box-measured 2026-09-09) while any first/last-wins single read certifies one side
 *  of a crafted `extensions: []` + block-seq pair, so >1 occurrence THROWS (both dup orders, never a
 *  silent clean). `files:` needs no twin guard: this leg never reads it — data-side facts come from
 *  the actual data.tar.gz member listing, not from metadata. */
export function gemDeclaredExtensions(metadata: string): string[] {
  const occurrences = [...metadata.matchAll(GEM_EXTENSIONS_KEYS)];
  if (occurrences.length > 1) {
    throw new Error(`duplicate extensions: key (${occurrences.length} top-level declarations) — cannot certify which one rubygems loads (psych is last-wins); failing closed`);
  }
  const m = occurrences[0];
  if (m === undefined) return [];
  const rest = (m[1] ?? "").trim();
  if (rest === "") {
    const items: string[] = [];
    for (const line of metadata.slice((m.index ?? 0) + m[0].length + 1).split("\n")) {
      if (line.trim() === "" || GEM_YAML_COMMENT.test(line)) continue;
      const item = GEM_YAML_SEQ_ITEM.exec(line);
      if (item !== null) {
        items.push((item[1] as string).trim());
        continue;
      }
      if (GEM_YAML_KEY_TERM.test(line)) break;
      throw new Error(`unrecognized line inside the extensions: block (${JSON.stringify(line.slice(0, 60))}) — cannot certify the build list clean`);
    }
    return items;
  }
  if (rest === "[]") return [];
  if (rest.startsWith("[") && rest.endsWith("]")) {
    return rest
      .slice(1, -1)
      .split(",")
      .map((s) => s.trim().replace(/^["']|["']$/gu, ""))
      .filter((s) => s !== "");
  }
  throw new Error(`unrecognized extensions: declaration in metadata.gz (${JSON.stringify(rest.slice(0, 60))}) — cannot certify the build list clean`);
}

/** Plan R3b AC: every declared extension must have a matching extconf.rb in data.tar.gz; each
 *  unmatchable build gets EXACTLY ONE MEDIUM note (dupes in the declaration collapse to one row),
 *  never a silent clean and never a second note for the same miss. */
function gemUnmatchedExtensionHits(metadata: string, dataRels: ReadonlySet<string>): ResidueHit[] {
  const hits: ResidueHit[] = [];
  const noted = new Set<string>();
  for (const entry of gemDeclaredExtensions(metadata)) {
    const expected = normalizeRel(entry.endsWith(`/${GEM_EXTCONF_BASENAME}`) ? entry : `${entry}/${GEM_EXTCONF_BASENAME}`);
    if (dataRels.has(expected) || noted.has(expected)) continue;
    noted.add(expected);
    hits.push({
      rule: RESIDUE_GEM_UNMATCHED_EXT_RULE,
      severity: "MEDIUM",
      message: `metadata.gz declares extension '${entry}' but data.tar.gz contains no '${expected}' — the native build is unmatchable: rubygems cannot run an extconf that is not shipped (plan R3b: never a silent clean)`,
      fileRel: expected,
      patternId: "gem-unmatched-extension",
    });
  }
  return hits;
}

/** Full rubygems leg over the UNPACKED data tree (pkgDir = inner extraction root, rels = its files)
 *  plus the gunzipped metadata.gz text. Scan set (plan R3b): every file gets the artifact-wide T4
 *  sweep + the auto-load/hook lane; install-time-reachable files (extconf.rb anywhere, plugin files,
 *  hook-registering files) additionally get the family scan (T2/T3/xmgr) — bin/lib/Rakefile at rest
 *  do NOT (reachability decision, §8). extconf.rb alone gets the write-confinement lane. */
export function residueGemHits(pkgDir: string, rels: readonly string[], metadata: string): ResidueHit[] {
  const hits: ResidueHit[] = [];
  const dataRels = new Set(rels.map(normalizeRel));
  for (const raw of rels) {
    const rel = normalizeRel(raw);
    const text = readText(pkgDir, rel);
    if (text === null) continue;
    const base = basename(rel);
    const isExtconf = base === GEM_EXTCONF_BASENAME;
    const persistence = gemPersistenceHit(rel, text);
    if (persistence !== null) hits.push(persistence);
    if (isExtconf || persistence !== null) hits.push(...familyHits(rel, text, GEM_WORDING));
    if (isExtconf) hits.push(...gemConfinementHits(rel, text));
    const t4 = t4HitFor(rel, text);
    if (t4 !== null) hits.push(t4);
  }
  hits.push(...gemUnmatchedExtensionHits(metadata, dataRels));
  return hits;
}
