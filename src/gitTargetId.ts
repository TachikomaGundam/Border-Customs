// Single source of truth for git push-target ids: `git:<name>` for named
// remotes, `git:#<index>` for unnamed ones (index = position in
// cfg.targets.git.remotes). Previously every site re-derived
// `git:${name ?? sanitizeUrl(url)}` — for local-path urls sanitizeUrl
// collapses to '[invalid-url-redacted]', so TWO unnamed remotes produced the
// SAME id and target→remote resolution first-matched one of them (double-push
// one remote, never push the other).
//
// Safety argument for index-keyed ids: border.yaml content feeds
// computeConfigDigest → the fingerprint key, so any remote-set reordering or
// edit yields a NEW key; push records are always consulted key-matched
// (pushesFor / pushRecords filter by key), so a `git:#N` id can never be
// confused across configs.
export function gitTargetId(remote: { readonly name?: string | undefined }, index: number): string {
  return `git:${remote.name ?? `#${index}`}`;
}
