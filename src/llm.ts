// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 18
//
// Public surface of the LLM bundle contract (plan names this module src/llm.ts;
// the implementation lives in src/llm/* to keep each file single-purpose):
//   - `border llm-request` → src/llm/bundle.ts (masked review bundle from the
//     newest ledger record matching the current fingerprint),
//   - `border llm-ingest`  → src/llm/ingest.ts (strict C1 validation, forced
//     engine:"agent", {llm:true} record via the todo-14 ledger seam).
// G30: border never calls an LLM API. The bundle is a file; the operator's
// agent reads it, authors findings JSON, and feeds llm-ingest back.
export { DATA_BOUNDARY, PATCH_LIMIT_BYTES, runLlmRequestCore, type BundleFileDelta, type LlmRequestBundle } from "./llm/bundle.ts";
export { runLlmIngestCore } from "./llm/ingest.ts";
