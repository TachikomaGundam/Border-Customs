// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 17,
//   re-wired per .omo/plans/border-push-channels.md todo C2 (re-export shim)
//
// Re-export shim for the todo-17 import paths (tests included, unchanged):
// the PyPI executor now lives in ../channels/pypi.ts (twine probe, upload argv
// and record semantics verbatim; seam names twineBinPath/TWINE_BIN preserved).
// Nothing is implemented here. Stays G28-guarded by construction: this file
// carries no credential vocabulary (the guard test scans this source).
export { runPypiPublish } from "../channels/pypi.ts";
export type { PypiPublishInput } from "../channels/pypi.ts";