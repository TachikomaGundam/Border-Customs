// provenance: border-inspect-roadmap.md W1.1 — `border scan` spec grammar.
//
// `[ecosystem:]name@version`, default npm. A scoped npm name starts with '@'
// so the name/version split happens at the LAST '@' (npm's own disambiguation
// rule). Anything malformed — missing version, unknown ecosystem, traversal
// shapes, stray whitespace/slashes outside the scoped grammar — is an
// UnknownArgError, which the CLI translates to the exit-2 + usage contract.
import { UnknownArgError } from "../cli/exit.ts";

export const ECOSYSTEMS = ["npm", "pypi", "crates", "rubygems"] as const;
export type ScanEcosystem = (typeof ECOSYSTEMS)[number];

export type ScanSpec = {
  readonly ecosystem: ScanEcosystem;
  readonly name: string;
  readonly version: string;
};

export const SCAN_SPEC_USAGE =
  "usage: border scan <[ecosystem:]name@version> — e.g. border scan puppeteer@23.11.1 | pypi:requests@2.32.3 | crates:serde@1.0.219 | rubygems:rails@7.1.1";

// Charsets pin registry-legal shapes and reject path-traversal / injection
// vectors before any URL is built or file written: names must start
// alphanumeric (scoped: '@' + segment '/' + segment), versions likewise.
const PLAIN_NAME = /^[A-Za-z0-9][A-Za-z0-9._+-]*$/;
const SCOPED_NAME = /^@[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/;
const VERSION = /^[A-Za-z0-9][A-Za-z0-9._+-]*$/;

const bad = (why: string): never => {
  throw new UnknownArgError(`${why}; ${SCAN_SPEC_USAGE}`);
};

export function parseScanSpec(raw: string): ScanSpec {
  const text = raw.trim();
  if (text.length === 0) return bad("empty spec");

  let ecosystem: ScanEcosystem = "npm";
  let rest = text;
  const colon = text.indexOf(":");
  if (colon >= 0) {
    const prefix = text.slice(0, colon);
    const found = ECOSYSTEMS.find((e) => e === prefix);
    if (found === undefined) {
      return bad(`unknown ecosystem '${prefix}' — expected one of: ${ECOSYSTEMS.join(", ")}`);
    }
    ecosystem = found;
    rest = text.slice(colon + 1);
    if (rest.length === 0) return bad("missing package name after the ecosystem prefix");
  }

  const scoped = rest.startsWith("@");
  const at = rest.lastIndexOf("@");
  if (at <= 0) return bad(`spec '${raw}' is missing '@version'`);
  const name = rest.slice(0, at);
  const version = rest.slice(at + 1);

  if (!(scoped ? SCOPED_NAME : PLAIN_NAME).test(name)) {
    return bad(`invalid package name '${name}'`);
  }
  if (!VERSION.test(version)) {
    return bad(`invalid version '${version}' in spec '${raw}'`);
  }
  return { ecosystem, name, version };
}
