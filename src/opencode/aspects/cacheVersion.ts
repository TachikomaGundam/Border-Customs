// provenance: .omo/plans/border-opencode-inspect.md T1 — aspect 1: cache-version.
//
// Internal truth of the Route-B cache dirs: each `border-customs@*` directory
// must carry a readable package.json version AND a plugin marker line whose
// version agrees with it; a dir cached under an exact-pin spec must report
// that version. The "no cache directory while config declares the plugin"
// case is the NOT-CACHED CANNOT — its detail line starts with the literal
// `NOT-CACHED:` because the drift-watch shell maps exactly that token to
// rc 0 (plan B2, backward compatibility with tools/plugin-drift-watch.mjs
// :84/:103).
import { splitNpmSpec } from "../jsonconfig.ts";
import { PLUGIN_MARKER, type AspectResult, type Facts } from "../contract.ts";

const isExactVersion = (spec: string): boolean => /^\d+\.\d+\.\d+([-+].*)?$/.test(spec);

export function verifyCacheVersion(facts: Facts): AspectResult {
  const id = "cache-version" as const;
  const { cacheDirs, configs, cacheRoot, pkg } = facts;
  const errored = configs.filter((c) => c.status === "error").map((c) => c.path);
  const declared = configs.some((c) => c.specs.length > 0);
  const where = configs.map((c) => `${c.path} [${c.status}]`).join(", ");

  if (cacheDirs.length === 0) {
    if (errored.length > 0) {
      return { id, verdict: "CANNOT", detail: `no cache directory under ${cacheRoot} and the configuration is unreadable (${errored.join(", ")}) — cannot tell whether a Route-B load is claimed` };
    }
    if (declared) {
      return { id, verdict: "CANNOT", detail: `NOT-CACHED: ${pkg} is declared (${configs.flatMap((c) => [...c.specs]).join(", ")}) but no cache directory exists under ${cacheRoot} — the load claim has no bytes behind it` };
    }
    return { id, verdict: "PASS", detail: `no ${pkg} cache directory under ${cacheRoot} and none declared (${where}) — Route B not in use, nothing to be stale` };
  }

  const pins = new Set(
    configs
      .flatMap((c) => [...c.specs])
      .map((s) => splitNpmSpec(s).spec)
      .filter((s): s is string => s !== null && isExactVersion(s)),
  );
  const problems: string[] = [];
  for (const d of cacheDirs) {
    if (d.packageVersion === null) {
      problems.push(`${d.dir}: package.json missing or unreadable`);
    }
    if (d.markerLine === null) {
      problems.push(`${d.dir}: plugin/border.ts missing or unreadable in the cached package`);
    } else if (d.markerVersion === null) {
      problems.push(`${d.dir}: plugin/border.ts first line lacks the marker '${PLUGIN_MARKER}'`);
    } else if (d.packageVersion !== null && d.markerVersion !== d.packageVersion) {
      problems.push(`${d.dir}: marker says ${d.markerVersion}, package.json says ${d.packageVersion}`);
    }
    if (pins.has(d.tag) && d.packageVersion !== null && d.packageVersion !== d.tag) {
      problems.push(`${d.dir}: cached under exact spec '${d.tag}' but the package reports ${d.packageVersion}`);
    }
  }
  if (problems.length > 0) {
    return { id, verdict: "FAIL", detail: problems.join("; ") };
  }
  return {
    id,
    verdict: "PASS",
    detail: `cache self-consistent: ${cacheDirs.map((d) => `${d.tag}->${d.packageVersion ?? "?"}`).join(", ")}`,
  };
}
