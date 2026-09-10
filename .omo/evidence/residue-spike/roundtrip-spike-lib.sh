#!/usr/bin/env bash
# roundtrip-spike-lib.sh — shared manifest/diff helpers for the W2.0
# sandbox-roundtrip feasibility spike (border 0.4.0 `border roundtrip`).
#
# Manifest format (sorted, tab-separated, one line per fs object):
#   F<TAB>/abs/path<TAB>octal-mode<TAB>sha256-of-content (or "-" if unhashed)
#   L<TAB>/abs/path<TAB>octal-mode<TAB>link-target
#   D<TAB>/abs/path<TAB>octal-mode<TAB>-
# Deliberately content+mode+type only — NO mtime/inode, so overlayfs copy-up
# (which changes inode/mtime but not bytes) cannot pollute docker diffs.
# Spike-acceptable caveat: paths containing TAB/newline break parsing; planted
# fixtures never use them.
#
# Root spec: <abs-path>[:h] — ":h" requests content sha256; without it files
# are path+mode+type only. Rationale measured in ROUNDTRIP-SPIKE.md: shared
# host /tmp is 15.5GB/512K files; full hashing there is neither feasible nor
# noise-free (other tenants churn it).
#
# Every external command is timeout'd (hard boundary). RT_TO is the general cap.
set -u
RT_TO=${RT_TO:-180}

rt_snapshot() {
  # rt_snapshot <out.manifest> <abs-exclusion ...> -- <rootspec ...>
  local out=$1; shift
  local excl=()
  while [ "$1" != "--" ]; do excl+=("$1"); shift; done
  shift
  local tmp
  tmp=$(mktemp -d /tmp/rt-snap.XXXXXX)
  local root e san
  local -a prune=()
  if [ ${#excl[@]} -gt 0 ]; then
    for e in "${excl[@]}"; do prune+=( -path "$e" -o ); done
    prune+=( -false )
  else
    prune=( -false )
  fi
  : >"$tmp/entries"
  : >"$tmp/files-hashed.z"
  : >"$tmp/files-plain.z"
  for spec in "$@"; do
    case $spec in
      *:h) root=${spec%:h}; hash=1 ;;
      *)   root=$spec;        hash=0 ;;
    esac
    [ -d "$root" ] || continue
    # || true: shared /tmp holds other tenants' unreadable dirs (EACCES rc=1)
    find "$root" -xdev \( "${prune[@]}" \) -prune -o \
      -type f -printf 'f\t%p\t%m\n' >>"$tmp/entries" 2>"$tmp/find-err" || true
    find "$root" -xdev \( "${prune[@]}" \) -prune -o \
      -type l -printf 'l\t%p\t%m\t%l\n' >>"$tmp/entries" 2>>"$tmp/find-err" || true
    find "$root" -xdev \( "${prune[@]}" \) -prune -o \
      -type d -printf 'd\t%p\t%m\n' >>"$tmp/entries" 2>>"$tmp/find-err" || true
    if [ "$hash" = 1 ]; then
      find "$root" -xdev \( "${prune[@]}" \) -prune -o \
        -type f -print0 >>"$tmp/files-hashed.z" 2>>"$tmp/find-err" || true
    else
      find "$root" -xdev \( "${prune[@]}" \) -prune -o \
        -type f -print0 >>"$tmp/files-plain.z" 2>>"$tmp/find-err" || true
    fi
  done
  # || true: files vanished between enumeration and hashing are benign races on
  # a shared /tmp; the diff will surface any *systematic* loss as ADDED/REMOVED.
  timeout "$RT_TO" bash -c 'xargs -0 -r sha256sum' <"$tmp/files-hashed.z" \
    >"$tmp/hashes" 2>"$tmp/hash-err" || true
  # getline-in-BEGIN: the NR==FNR idiom silently swallows ALL records when the
  # hashes file is empty (hash-less roots only) — FNR restarts per file, so
  # NR==FNR stays true on the entries file. Found via 0-line /tmp manifests.
  LC_ALL=C awk -F'\t' -v HF="$tmp/hashes" '
    BEGIN { while ((getline line < HF) > 0) { h = substr(line,1,64); p = substr(line,67); hash[p] = h } close(HF) }
    $1 == "f" { print "F\t" $2 "\t" $3 "\t" (($2 in hash) ? hash[$2] : "-") }
    $1 == "l" { print "L\t" $2 "\t" $3 "\t" $4 }
    $1 == "d" { print "D\t" $2 "\t" $3 "\t-" }
  ' "$tmp/entries" | LC_ALL=C sort >"$out"
  rm -rf "$tmp"
  wc -l <"$out"
}

rt_diff() {
  # rt_diff <before.manifest> <after.manifest> — MODIFIED/ADDED/REMOVED keyed
  # on (type,path); exit 0 iff manifests identical. join-based: O(n log n).
  local before=$1 after=$2
  local tmp
  tmp=$(mktemp -d /tmp/rt-diff.XXXXXX)
  # serialize: key=$1$2 joined by \x1f, payload = mode, hash
  LC_ALL=C awk -F'\t' 'BEGIN{OFS="\x1f"} {print $1 $2, $3, $4}' "$before" \
    | LC_ALL=C sort -t$'\x1f' -k1,1 >"$tmp/b"
  LC_ALL=C awk -F'\t' 'BEGIN{OFS="\x1f"} {print $1 $2, $3, $4}' "$after" \
    | LC_ALL=C sort -t$'\x1f' -k1,1 >"$tmp/a"
  cut -d$'\x1f' -f1 "$tmp/b" >"$tmp/bk"
  cut -d$'\x1f' -f1 "$tmp/a" >"$tmp/ak"
  local added removed modified
  added=$(LC_ALL=C comm -13 "$tmp/bk" "$tmp/ak")
  removed=$(LC_ALL=C comm -23 "$tmp/bk" "$tmp/ak")
  modified=$(LC_ALL=C join -t$'\x1f' -1 1 -2 1 "$tmp/b" "$tmp/a" \
    | LC_ALL=C awk -F$'\x1f' '$2$3 != $4$5 {print $1 "|" $2 "|" $3} ')
  printf 'ADDED(%s)\n'    "$(printf '%s' "$added"    | grep -c . || true)"
  [ -n "$added" ]    && printf '%s\n'    "$added"    | sed 's/^/A\t/'
  printf 'REMOVED(%s)\n'  "$(printf '%s' "$removed"  | grep -c . || true)"
  [ -n "$removed" ]  && printf '%s\n'    "$removed"  | sed 's/^/R\t/'
  printf 'MODIFIED(%s)\n' "$(printf '%s' "$modified" | grep -c . || true)"
  [ -n "$modified" ] && printf '%s\n'    "$modified" | sed 's/^/M\t/'
  rm -rf "$tmp"
  [ -z "$added" ] && [ -z "$removed" ] && [ -z "${modified%$'\n'}" ]
}

rt_ctr_snapshot() {
  # rt_ctr_snapshot <container> <out.manifest> <abs-exclusion ...> -- /
  # Runs the same manifest pipeline INSIDE a container (POSIX sh + GNU find +
  # sha256sum + POSIX awk; debian-slim has all). Reads only: overlayfs
  # copy-up is not triggered by the scan itself.
  local ctr=$1 out=$2; shift 2
  local excl=()
  while [ "$1" != "--" ]; do excl+=("$1"); shift; done
  shift
  # ":h" suffix is accepted for symmetry with rt_snapshot; the container lane
  # ALWAYS hashes, so it is stripped here rather than branching remotely.
  local roots="" spec
  for spec in "$@"; do roots="$roots ${spec%:h}"; done
  local -a prune=()
  if [ ${#excl[@]} -gt 0 ]; then
    local e; for e in "${excl[@]}"; do prune+=( "-path '$e' -o " ); done
    prune+=( "-false " )
  else
    prune=( "-false " )
  fi
  local pexpr="${prune[*]}"
  timeout "$RT_TO" docker exec "$ctr" sh -c "
    set -u; tmp=\$(mktemp -d -p /dev/shm)
    : >\$tmp/e; : >\$tmp/h
    for r in $roots; do
      find \$r -xdev \\( $pexpr \\) -prune -o -type f -printf 'f\t%p\t%m\n' >>\$tmp/e 2>>\$tmp/fe || true
      find \$r -xdev \\( $pexpr \\) -prune -o -type l -printf 'l\t%p\t%m\t%l\n' >>\$tmp/e 2>>\$tmp/fe || true
      find \$r -xdev \\( $pexpr \\) -prune -o -type d -printf 'd\t%p\t%m\n' >>\$tmp/e 2>>\$tmp/fe || true
      find \$r -xdev \\( $pexpr \\) -prune -o -type f -print0 2>>\$tmp/fe >>\$tmp/fz || true
    done
    xargs -0 -r sha256sum <\$tmp/fz >\$tmp/h 2>>\$tmp/fe || true
    awk -v HF=\$tmp/h '
      BEGIN { FS=\"\t\"; OFS=\"\t\"; while ((getline line < HF) > 0) { pfx=index(line,\"  \"); hash[substr(line,pfx+2)]=substr(line,1,pfx-1) } close(HF) }
      { t=\$1; if (t==\"f\") print \"F\", \$2, \$3, (\$2 in hash ? hash[\$2] : \"-\")
        else if (t==\"l\") print \"L\", \$2, \$3, \$4
        else if (t==\"d\") print \"D\", \$2, \$3, \"-\" }
    ' \$tmp/e | LC_ALL=C sort
    rm -rf \$tmp
  " >"$out"
  wc -l <"$out"
}
