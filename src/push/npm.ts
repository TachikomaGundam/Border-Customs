// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 17,
//   re-wired per .omo/plans/border-push-channels.md todo C2 (re-export shim)
//
// Re-export shim for the todo-17 import paths (tests included, unchanged):
// the shared same-bytes publish core now lives in ./core.ts (see its header
// for the gate → re-hash → dry-run/confirm → spawn stdio:'inherit' → record
// pipeline and the G37 immutability-policy citations) and the npm executor in
// ../channels/npm.ts. Nothing is implemented here — every export re-points to
// the C2 core/descriptors. Stays G28-guarded by construction: this file
// carries no credential vocabulary (the guard test scans this source).
export { PUBLISH_WARNING, writers, requirePassedRecord, rehashRecordedArtifacts, blockingProbeFindings, spawnInherit } from "./core.ts";
export type { LineWriter, PublishInput } from "./core.ts";
export { NPM_DEFAULT_REGISTRY, runNpmPublish } from "../channels/npm.ts";
export type { NpmPublishInput } from "../channels/npm.ts";
export { runPypiPublish } from "../channels/pypi.ts";
export type { PublishTarget } from "../channels/registry.ts";