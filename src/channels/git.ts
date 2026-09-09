// provenance: original clean-room implementation per .omo/plans/border-push-channels.md todo C2
//
// GitChannel — thin registration only (id "git", order 0, configured-check).
// Per plan todo C2: the deep git leg (remotes, ls-remote, ff-guard) stays in
// src/push/git.ts and the pushstate gitState block — untouched here. Target-id
// derivation continues to flow through the existing src/gitTargetId.ts
// (git:<name> / git:#index).
import type { BorderConfig } from "../config.ts";
import type { GitChannel } from "./types.ts";

export const gitChannel: GitChannel = {
  id: "git",
  order: 0,
  configured: (cfg: BorderConfig): boolean => cfg.targets.git.remotes.length > 0,
};