// provenance: Abathur handoff 2026-11-01 (rule-class-3 false positives, commit b61b42a).
//
// `.env` is a disk location inside a string literal and a property access inside
// code — the same characters, a SYNTACTIC distinction no receiver-shaped regex can
// draw (opts vs secrets are both plain identifiers; proven by the handoff's
// read-aloud round). This module answers one question for JS/TS sources: at which
// byte spans does the file contain string-like literal text?
//
// Contract (handoff §3, decided there):
//   * string literals, no-substitution template literals, and template fragments
//     (head/middle/tail) are literal spans — the ${...} regions are INCLUDED,
//     deliberately conservative: a location inside an interpolation is still the
//     author writing a location into source text;
//   * comments are NOT literal spans (the AST visitor never yields them);
//   * parse diagnostics ⇒ null ⇒ the CALLER keeps the old behavior and emits the
//     required stderr diagnostic. This module stays silent and side-effect free.
// typescript is a real dependency resolved at runtime (esbuild keeps it external;
// the createRequire banner in the bundle resolves it from the installed package).
import { createRequire } from "node:module";

const JS_TS_KINDS: Readonly<Record<string, string>> = {
  ".js": "JS", ".jsx": "JSX", ".mjs": "JS", ".cjs": "JS",
  ".ts": "TS", ".tsx": "TSX", ".mts": "TS", ".cts": "TS",
};

export type LiteralSpan = { readonly start: number; readonly end: number };

export function isJsTsPath(filePath: string): boolean {
  const dot = filePath.lastIndexOf(".");
  return dot >= 0 && JS_TS_KINDS[filePath.slice(dot).toLowerCase()] !== undefined;
}

let tsApi: any; // eslint-disable-line @typescript-eslint/no-explicit-any -- compiler API is structural here
function loadTs(): any {
  if (tsApi === undefined) {
    try {
      tsApi = createRequire(import.meta.url)("typescript");
    } catch {
      tsApi = null; // resolution failure behaves like a parse failure: caller keeps old behavior + diagnostic
    }
  }
  return tsApi;
}

/** Literal spans for a JS/TS source; null when no tree can be trusted. */
export function literalSpans(filePath: string, text: string): LiteralSpan[] | null {
  const ts = loadTs();
  if (ts === null) return null;
  const dot = filePath.lastIndexOf(".");
  const kind = JS_TS_KINDS[filePath.slice(dot).toLowerCase()] ?? "TS";
  const scriptKind = ts.ScriptKind[kind as keyof typeof ts.ScriptKind];
  let sf: any; // eslint-disable-line @typescript-eslint/no-explicit-any
  try {
    sf = ts.createSourceFile(filePath, text, scriptKind, /* setParentNodes */ true);
  } catch {
    return null;
  }
  const parseDiagnostics: unknown[] = sf.parseDiagnostics ?? [];
  if (parseDiagnostics.length > 0) return null;
  const spans: LiteralSpan[] = [];
  const visit = (node: any): void => { // eslint-disable-line @typescript-eslint/no-explicit-any
    const k = node.kind as number;
    if (
      k === ts.SyntaxKind.StringLiteral
      || k === ts.SyntaxKind.NoSubstitutionTemplateLiteral
      || k === ts.SyntaxKind.TemplateHead
      || k === ts.SyntaxKind.TemplateMiddle
      || k === ts.SyntaxKind.TemplateTail
    ) {
      spans.push({ start: node.getStart(sf), end: node.getEnd() });
    }
    node.forEachChild(visit);
  };
  visit(sf);
  spans.sort((a: LiteralSpan, b: LiteralSpan) => a.start - b.start);
  return spans;
}

/** Membership: is offset inside any span? Linear with early exit — literal
 *  spans nest (template head inside full template), and nested intervals
 *  defeat a plain binary walk (a right sibling can shadow its left ancestor). */
export function inSpan(spans: readonly LiteralSpan[], offset: number): boolean {
  for (const s of spans) {
    if (s.start > offset) break;
    if (offset < s.end) return true;
  }
  return false;
}
