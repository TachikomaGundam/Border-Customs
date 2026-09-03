# Problems — border-push-gate

Unresolved blockers and technical debt discovered during work on this plan.

_Auto-scaffolded by /start-work. Append new entries below - never overwrite._

---

## task-9 (identity allowlist) — gotchas for downstream todos (10/19)
- `git for-each-ref --format='... %(taggeremail)'` emits `<email>` WITH angle brackets — scanIdentity strips them; any future consumer of that atom must too.
- Plan's log format lacks %H; identity.ts prepends `%H` to the five plan fields (findings must list shas). todo 10 wires refSet: each refSet entry is passed verbatim to `git log` (revs, ranges `a..b`, even `--not` forms work); empty refSet skips the commit leg but the tag leg still runs unconditionally.
- allowBots=true replaces the email AND name check for `*[bot]@users.noreply.github.com` (GitHub-issued display names end in `[bot]`; requiring a names glob too would be friction without security value).
- Identity findings are deliberately NOT registered with TextSanitizer (evidence must stay readable in the report); valueDigest/snippet still via redact().
