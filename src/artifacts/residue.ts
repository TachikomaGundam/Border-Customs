// provenance: RESIDUE-CONTRACT.md §1.6/§4/§5.3 + adjudications #1-#5 (R2, border-residue-gate).
// Classifier ONLY — every pattern/rule-id table lives in src/rules/residueMatchers.ts (grep AC 5).
// FAIL-CLOSED contract: any unreadable file, missing hook target, multi-hop/odd grammar, or a
// single out-of-signature literal returns signatureId=null and the CALLER keeps today's verbatim
// lifecycle-script CRITICAL. T1 requires ALL §1.6 clauses; it never widens (plan Must-NOT).
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import type { Finding, Severity } from "../findings.ts";
import { redact, type TextSanitizer } from "../redact.ts";
import { NPM_TARGET_LABEL, sanitizeOut } from "./npmPack.ts";

import {
  FAMILY_PATTERNS,
  MARKER_BEGIN,
  MARKER_END,
  MARKER_INVERSE_SURFACE,
  MARKER_REMOVE_SHAPE,
  MARKER_WRITE_SHAPE,
  RESIDUE_PAIRING_RULE,
  RESIDUE_SEVERITIES,
  RESIDUE_T1_SIGNATURE_ID,
  RESIDUE_T2_RULE,
  RESIDUE_T3_RULE,
  RESIDUE_T4_RULE,
  RESIDUE_XMGR_RULE,
  RESOLVABLE_HOOK,
  T1_ABS_PATH_LITERAL,
  T1_ALLOWED_ABS_PATHS,
  T1_ALLOWED_MODULES,
  T1_DYNAMIC_REF,
  T1_FORBIDDEN_USER_PATH_MARKS,
  T1_HOOK_GRAMMAR,
  T1_LINE_CAP,
  T1_METAPROGRAMMING,
  T1_MODULE_REF,
  T1_REQUIRED_LITERALS,
  T1_SPAWN_ARGV0_IDENTIFIERS,
  T1_SPAWN_ARGV0_LITERALS,
  T1_SPAWN_CALL,
  T1_SPAWN_NAME,
  T1_WRITE_ARGV0_FORMS,
  T1_WRITE_CALL,
  T1_WRITE_NAME,
  XMGR_LABELS,
  isPlainHookString,
  verbsAllCalled,
} from "../rules/residueMatchers.ts";
/** Artifact-target Findings for residue rows — same native shape as npm.ts's lifecycle rows.
 *  `sep` attributes rows to their archive: npm `package/x`, pypi `<archive>!<inner>` (plan R3a AC). */
export function residueFindings(hits: readonly ResidueHit[], o: { root: string; identity: string; sanitizer?: TextSanitizer; sep?: string }): Finding[] {
  return hits.map((hit) => {
    // VERIFIER-REPORT-R3A N2: a lane-specific patternId separates digests when two independent
    // detectors emit the same (rule, file) pair — otherwise one allow-list entry mutes both rows.
    // Absent patternId keeps the pre-R3a key byte-identical, so every npm 0.2.0-pinned digest holds.
    const digest = redact(`${o.identity}:residue:${hit.rule}:${hit.fileRel}${hit.patternId === undefined ? "" : `:${hit.patternId}`}`);
    return {
      rule: hit.rule,
      severity: hit.severity,
      target: NPM_TARGET_LABEL,
      path: o.root === "" ? hit.fileRel : `${o.root}${o.sep ?? "/"}${hit.fileRel}`,
      engine: "native",
      message: sanitizeOut(o.sanitizer, hit.message),
      valueDigest: digest.valueDigest,
      snippet: digest.snippet,
    };
  });
}

export type ResidueHit = {
  readonly rule: string;
  readonly severity: Severity;
  readonly message: string;
  /** path relative to the extracted package root (`package/`); residueFindings scopes + attributes. */
  readonly fileRel: string;
  /** digest discriminator for lanes that can double up on one (rule, file) pair (R3A-N2);
   *  undefined = the 0.2.0 key shape, NEVER set on rows whose digests are golden-pinned. */
  readonly patternId?: string;
};

export type HookScan = {
  /** non-null ONLY when every §1.6 clause holds; names the matched signature id. */
  readonly signatureId: string | null;
  /** T2/T3/cross-manager rows for the resolved hook file (T4/marker checks come from the sweep). */
  readonly hits: readonly ResidueHit[];
};

const SCAN_LINE_CAP = 100;
const SWEEP_EXTS = new Set(["bash", "bat", "cjs", "cmd", "js", "json", "lua", "mjs", "pl", "ps1", "py", "rb", "rs", "sh", "zsh"]);
const SWEEP_MAX_BYTES = 512 * 1024;

/** rel paths are package-root-relative; extract-list entries arrive as `package/<rel>`,
 *  manifest bin values as `./<rel>` — both normalize to `<rel>`. */
function toPkgRel(rel: string): string {
  const bare = rel.startsWith("package/") ? rel.slice("package/".length) : rel;
  return bare.replace(/^\.\//, "");
}

export function readText(pkgDir: string, rel: string): string | null {
  try {
    const abs = join(pkgDir, rel);
    if (!abs.startsWith(pkgDir) || !existsSync(abs)) return null;
    const buf = readFileSync(abs);
    if (buf.byteLength > SWEEP_MAX_BYTES) return null;
    if (buf.subarray(0, 8192).includes(0)) return null; // binary
    return buf.toString("utf8");
  } catch {
    return null;
  }
}

export function evidenceLine(text: string, pattern: RegExp): string {
  for (const line of text.split("\n")) {
    if (pattern.test(line)) {
      const trimmed = line.trim();
      return trimmed.length > SCAN_LINE_CAP ? `${trimmed.slice(0, SCAN_LINE_CAP)}…` : trimmed;
    }
  }
  return "";
}

/** Ecosystem wording for the cross-manager row (`<what> code … outside the <ledger> ledger`).
 *  npm keeps the 0.2.0 byte-identical strings; R3a legs name their own build phase/ledger. */
export type FamilyWording = { readonly what: string; readonly ledger: string };
export const FAMILY_WORDING: Readonly<Record<"npm" | "pypi" | "crates", FamilyWording>> = {
  npm: { what: "lifecycle", ledger: "npm" },
  pypi: { what: "build-hook", ledger: "pip" },
  crates: { what: "build-script", ledger: "cargo" },
};

/** Per-file T2/T3/cross-manager scan (T4 + marker pair-detection are artifact-wide — see sweep). */
export function familyHits(fileRel: string, text: string, w: FamilyWording = FAMILY_WORDING.npm): ResidueHit[] {
  const byRule = new Map<string, { first: string; labels: string[] }>();
  for (const fam of FAMILY_PATTERNS) {
    if (fam.rule === RESIDUE_T4_RULE || fam.rule === RESIDUE_PAIRING_RULE) continue;
    if (!fam.pattern.test(text)) continue;
    const bucket = byRule.get(fam.rule) ?? { first: "", labels: [] as string[] };
    if (bucket.first === "") bucket.first = `${fam.id} "${evidenceLine(text, fam.pattern)}"`;
    const label = XMGR_LABELS[fam.id];
    if (label !== undefined) bucket.labels.push(label);
    byRule.set(fam.rule, bucket);
  }
  const hits: ResidueHit[] = [];
  for (const [rule, { first, labels }] of byRule) {
    const severity = RESIDUE_SEVERITIES[rule];
    if (severity === undefined) continue;
    const message =
      rule === RESIDUE_XMGR_RULE
        ? `${w.what} code in '${fileRel}' spawns foreign package manager(s): ${labels.join(", ")} — writes land outside the ${w.ledger} ledger and re-run on every consumer install (aihr incident shape)`
        : rule === RESIDUE_T2_RULE
          ? `install-time code in '${fileRel}' reaches the network: ${first} — remote bytes run on every consumer install (T2); pin prebuilt artifacts instead`
          : `install-time code in '${fileRel}' writes outside the package root: ${first} (T3)`;
    hits.push({ rule, severity, message, fileRel });
  }
  return hits;
}

/** B2: slice the first-argument expression text of the call whose `(` sits at `open` —
 *  paren/bracket/brace aware, quote aware, stopping at the top-level `,` or the closing `)`.
 *  Returns null on unbalanced input, which callers treat as an unrecognized shape (fail closed).
 *  This is deliberately ONE argument slice for a set membership test, not an expression parser. */
export function firstArgument(text: string, open: number): string | null {
  let depth = 0;
  let quote: string | null = null;
  for (let i = open; i < text.length; i += 1) {
    const ch = text.charAt(i);
    if (quote !== null) {
      if (ch === "\\") i += 1;
      else if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") quote = ch;
    else if (ch === "(" || ch === "[" || ch === "{") depth += 1;
    else if (ch === ")" || ch === "]" || ch === "}") {
      depth -= 1;
      if (depth === 0) return text.slice(open + 1, i);
    } else if (ch === "," && depth === 1) {
      return text.slice(open + 1, i);
    }
  }
  return null;
}

/** Concatenated bodies of every TOML section whose header line matches `header`
 *  (R3a scoping: pyproject [build-system] / cargo [..build-dependencies] only —
 *  a whole-manifest scan would false-positive on runtime [project]/[dependencies] entries). */
export function sectionBlock(text: string, header: RegExp): string {
  const body: string[] = [];
  let keep = false;
  for (const line of text.split("\n")) {
    if (line.startsWith("[")) keep = header.test(line);
    else if (keep) body.push(line);
  }
  return body.join("\n");
}

/** §57/plan-line-59 shared T4 primitive row (npm sweep and pypi/crates legs attribute per archive). */
export function t4HitFor(rel: string, text: string): ResidueHit | null {
  const t4 = FAMILY_PATTERNS.find((fam) => fam.rule === RESIDUE_T4_RULE && fam.pattern.test(text));
  if (t4 === undefined) return null;
  return {
    rule: RESIDUE_T4_RULE,
    severity: "CRITICAL",
    message: `packed file '${rel}' references an OS persistence primitive: ${t4.id} "${evidenceLine(text, t4.pattern)}" — runs on login/boot long after uninstall; blocked artifact-wide regardless of hook linkage (T4)`,
    fileRel: rel,
  };
}

/** Signature #1 evaluation — ALL §1.6 clauses or null (whitespace-normalized literal matching). */
function evaluateT1(pkgDir: string, hook: string): string | null {
  const trimmed = hook.trim();
  const grammar = T1_HOOK_GRAMMAR.exec(trimmed);
  if (grammar === null || !isPlainHookString(trimmed)) return null;
  const name = grammar[1];
  if (name === undefined) return null;
  const text = readText(pkgDir, name);
  if (text === null) return null; // missing/unreadable/binary ⇒ UNKNOWN ⇒ CRITICAL (fail-closed)
  if (text.split("\n").length - 1 > T1_LINE_CAP) return null; // §1.6-8 cap (189 lines in the anatomy)
  const norm = text.replace(/\s+/g, " ");
  for (const lit of T1_REQUIRED_LITERALS) if (!norm.includes(lit)) return null; // §1.6-3/5/6/7 + adj #1
  for (const mark of T1_FORBIDDEN_USER_PATH_MARKS) if (norm.includes(mark)) return null; // §1.6-5
  if (T1_METAPROGRAMMING.test(norm)) return null; // §1.6-9 (NB1): eval/new Function/globalThis[] never appear in the anatomy
  if (!verbsAllCalled(T1_WRITE_NAME, norm)) return null; // §1.6-9 (NB2): an un-called write-family name is an alias — out of grammar
  if (!verbsAllCalled(T1_SPAWN_NAME, norm)) return null; // §1.6-9 (NB3): same doctrine for spawn verbs — kills `const ex = cp.exec; ex(…)`
  for (const m of text.matchAll(T1_MODULE_REF)) {
    const spec = (m[1] ?? m[2] ?? m[3] ?? "").replace(/^node:/, "");
    if (!T1_ALLOWED_MODULES.includes(spec)) return null; // §1.6-2
  }
  for (const m of norm.matchAll(T1_DYNAMIC_REF)) {
    const spec = (m[1] ?? "").trim();
    const lit = /^"([^"]+)"$|^'([^']+)'$/.exec(spec);
    const mod = (lit?.[1] ?? lit?.[2] ?? "").replace(/^node:/, "");
    if (lit === null || !T1_ALLOWED_MODULES.includes(mod)) return null; // §1.6-2 exhaustive (B1)
  }
  for (const m of norm.matchAll(T1_WRITE_CALL)) {
    const argv0 = firstArgument(norm, (m.index ?? 0) + m[0].length - 1);
    if (argv0 === null || !T1_WRITE_ARGV0_FORMS.includes(argv0.replace(/\s+/g, ""))) return null; // §1.6-5 closed anatomy (B2)
  }
  for (const m of norm.matchAll(T1_SPAWN_CALL)) {
    const literal = m[1];
    const ident = m[2];
    if (literal !== undefined) {
      if (!T1_SPAWN_ARGV0_LITERALS.includes(literal)) return null; // §1.6-4
    } else if (ident !== undefined) {
      const bound = T1_SPAWN_ARGV0_IDENTIFIERS.find((b) => b.ident === ident);
      if (bound === undefined || !norm.includes(bound.proof)) return null;
    } else {
      return null;
    }
  }
  for (const m of text.matchAll(T1_ABS_PATH_LITERAL)) {
    const rest = m[1];
    if (rest === undefined || !T1_ALLOWED_ABS_PATHS.some((p) => rest.startsWith(p))) return null;
  }
  if (familyHits(name, text).length > 0) return null; // §1.6-5: any T2/T3/xmgr hit voids T1
  // T4 mentions (even in comments) void the signature too — the artifact-wide sweep
  // will still block independently, but a T1 badge must never ride on a persistence string.
  if (FAMILY_PATTERNS.some((fam) => fam.rule === RESIDUE_T4_RULE && fam.pattern.test(text))) return null;
  return RESIDUE_T1_SIGNATURE_ID;
}

export function scanNpmLifecycleHook(o: { pkgDir: string; hook: string }): HookScan {
  const signatureId = evaluateT1(o.pkgDir, o.hook);
  let hits: ResidueHit[] = [];
  if (signatureId === null && isPlainHookString(o.hook.trim())) {
    const resolved = RESOLVABLE_HOOK.exec(o.hook.trim());
    const rel = resolved?.[1];
    if (rel !== undefined) {
      const text = readText(o.pkgDir, rel);
      if (text !== null) hits = familyHits(rel, text); // total reads stay ≤2 files/hook
    }
  }
  return { signatureId, hits };
}

export function isSweepable(rel: string): boolean {
  return SWEEP_EXTS.has(rel.split(".").pop() ?? "") || rel.startsWith("bin/");
}

/** Artifact-wide T4 sweep + B2 marker pair-detection (§5.3 three static conditions, detection-only). */
export function sweepResidueNpmArtifact(o: { pkgDir: string; files: readonly string[]; binRels: readonly string[] }): ResidueHit[] {
  // §5.3(i) writer files / (ii) deletion-restore files, keyed by marker id-path bytes
  const hits: ResidueHit[] = [];
  const writes = new Map<string, string>();
  const removedIn = new Map<string, string>();
  let inverse = false;

  for (const entry of o.files) {
    const rel = toPkgRel(entry);
    if (!isSweepable(rel)) continue;
    const text = readText(o.pkgDir, rel);
    if (text === null) continue;

    const t4 = t4HitFor(rel, text);
    if (t4 !== null) hits.push(t4);

    const hasWrite = MARKER_WRITE_SHAPE.test(text);
    const hasRemove = MARKER_REMOVE_SHAPE.test(text);
    for (const m of text.matchAll(new RegExp(MARKER_BEGIN.source, "g"))) {
      const id = m[1];
      if (id === undefined) continue;
      if (hasWrite) writes.set(id, writes.get(id) ?? rel);
      else if (hasRemove) removedIn.set(id, rel); // BEGIN bytes appear only in a removal shape ⇒ dead inverse
    }
    if (hasRemove) {
      for (const m of text.matchAll(new RegExp(MARKER_END.source, "g"))) {
        const id = m[1];
        if (id !== undefined) removedIn.set(id, rel);
      }
    }
  }

  for (const binRel of o.binRels) {
    const text = readText(o.pkgDir, toPkgRel(binRel));
    if (text !== null && MARKER_INVERSE_SURFACE.test(text)) inverse = true;
  }

  for (const [id, fileRel] of writes) {
    const paired = removedIn.has(id) && inverse;
    hits.push({
      rule: RESIDUE_T3_RULE,
      severity: "HIGH",
      message:
        `install-time code in '${fileRel}' writes a '# BEGIN ${id}' marker block outside the package root (T3)` +
        (paired ? ` [pairing=verified: marker id '${id}' ships a remove path + CLI inverse; severity stays HIGH until 0.4.0]` : ""),
      fileRel,
    });
    if (!paired) {
      const missing = !removedIn.has(id) && !inverse ? "no remove path or CLI inverse" : !removedIn.has(id) ? "no remove path" : "no CLI inverse surface";
      hits.push({
        rule: RESIDUE_PAIRING_RULE,
        severity: "HIGH",
        message: `marker block '${id}' is written by '${fileRel}' but ${missing} ships in the artifact — the out-of-tree write has no undo surface (contract §5.3)`,
        fileRel,
      });
    }
  }
  for (const [id, fileRel] of removedIn) {
    if (writes.has(id)) continue;
    hits.push({
      rule: RESIDUE_PAIRING_RULE,
      severity: "MEDIUM",
      message: `'${fileRel}' removes/undoes marker block '${id}' that no packed file ever writes (dead inverse) — audit for a stripped or hidden write path (contract §5.3 note)`,
      fileRel,
    });
  }
  return hits;
}
