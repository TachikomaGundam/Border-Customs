// provenance: .omo/plans/border-opencode-v2-plugin.md T1 — V2 project-directory plugin
// discovery resolves <dir>/index directly (bypassing the package exports map, live-proven
// on cli beta-19271); this re-export lets the unpacked package directory itself serve as a
// V2 local plugin. Name-based imports continue to enter through exports["./server"].
import plugin from "./plugin/border.ts";

export default plugin;
