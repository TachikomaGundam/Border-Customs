#!/usr/bin/env bash
# roundtrip-spike-host-gemcargo.sh — host-lane verdict rows for rubygems +
# cargo, same plant/manifest/diff method as the npm/pypi host lanes.
# gem: arbitrary code runs at `gem build` (gemspec is Ruby) -> plant there.
# cargo: arbitrary code runs at build.rs -> plant there; cargo install --root
# + disposable CARGO_HOME.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
source "$HERE/roundtrip-spike-lib.sh"
SCRATCH=$(mktemp -d /tmp/rt-host-gc.XXXXXX)
PLANTPATHS=("/tmp/rt-gem-plant-tmp" "/var/tmp/rt-gem-plant-vartmp" "/etc/profile.d/rt-gem-plant.sh" "/usr/local/bin/rt-gem-plant"
            "/tmp/rt-cargo-plant-tmp" "/var/tmp/rt-cargo-plant-vartmp" "/etc/profile.d/rt-cargo-plant.sh" "/usr/local/bin/rt-cargo-plant")
rt_cleanup() { rm -f "${PLANTPATHS[@]}" 2>/dev/null || true; rm -rf "$SCRATCH"; }
trap rt_cleanup EXIT
rm -f "${PLANTPATHS[@]}" 2>/dev/null || true
EXCL_TMP=("/tmp/rt-snap.*" "/tmp/rt-diff.*" "/tmp/rt-host-*" "/tmp/rt-docker-*" "/tmp/rt-packdbg*" "/tmp/opencode*" "/tmp/pip-*" "/tmp/node-*" "/tmp/systemd-private-*" "/tmp/snap-private-tmp" "/tmp/.X11-unix" "/tmp/.ICE-unix" "/tmp/tmp.*" "/tmp/snap.*" "/tmp/vscode-*" "/tmp/.org.chromium.*" "/tmp/mcp*" "/tmp/abathur*" "/tmp/border-*")
obs() { # obs <tag> <home>
  local tag=$1
  local h=$2
  local out=$SCRATCH/obs-$tag.manifest
  local t0
  t0=$(date +%s)
  rt_snapshot "$out.home" -- "$h:h" >/dev/null
  rt_snapshot "$out.tmp"  "${EXCL_TMP[@]}" -- /tmp >/dev/null
  rt_snapshot "$out.rest" -- "/var/tmp:h" "/etc/profile.d:h" "/usr/local/bin:h" >/dev/null
  cat "$out.home" "$out.tmp" "$out.rest" | LC_ALL=C sort >"$out"
  echo "$tag entries=$(wc -l <"$out") elapsed=$(( $(date +%s)-t0 ))s"
}

echo '##### RUBYGEMS (host, -i + GEM_HOME + throwaway HOME) #####'
export HOME=$SCRATCH/ghome; mkdir -p "$HOME"
export XDG_CACHE_HOME=$HOME/.cache XDG_CONFIG_HOME=$HOME/.config
GS=$SCRATCH/gemsrc; mkdir -p "$GS/bin"
cat >"$GS/rt-gem-plant.gemspec" <<'RB'
require "fileutils"
%W[#{Dir.home}/.config/rt-gem-plant/rc-say.sh /tmp/rt-gem-plant-tmp /var/tmp/rt-gem-plant-vartmp /etc/profile.d/rt-gem-plant.sh /usr/local/bin/rt-gem-plant].each do |p|
  begin
    FileUtils.mkdir_p(File.dirname(p))
    File.write(p, p.end_with?(".sh") ? "export RT_GEM=1\n" : "gem plant\n")
    puts "PLANTED #{p}"
  rescue => e
    puts "PLANT-DENIED #{p} #{e.message[0,40]}"
  end
end
Gem::Specification.new do |s|
  s.name = "rt-gem-plant"; s.version = "0.0.1"; s.summary = "W2.0 spike fixture"
  s.authors = ["spike"]; s.files = ["bin/rt-gem-plant-exe"]; s.require_paths = ["lib"]
  s.bindir = "bin"; s.executables = ["rt-gem-plant-exe"]
end
RB
printf '#!/usr/bin/ruby\nputs "gem exe"\n' >"$GS/bin/rt-gem-plant-exe"
obs g-base "$HOME"
(cd "$GS" && timeout 300 gem build rt-gem-plant.gemspec 2>&1 | grep -E 'PLANT|File' | head -n 8)
mv "$GS"/rt-gem-plant-0.0.1.gem "$SCRATCH/"
export GEM_HOME=$SCRATCH/gems GEM_PATH=$SCRATCH/gems
timeout 300 gem install "$SCRATCH/rt-gem-plant-0.0.1.gem" --no-document -i "$GEM_HOME" 2>&1 | tail -n 2
obs g-mid "$HOME"
timeout 300 gem uninstall rt-gem-plant -x --force -i "$GEM_HOME" 2>&1 | tail -n 1
obs g-final "$HOME"
echo '--- gem acceptance diff (g-base before build -> g-final after uninstall):'
set +e; { rt_diff "$SCRATCH/obs-g-base.manifest" "$SCRATCH/obs-g-final.manifest"; echo "GEM_RC=$?"; } | head -n 14; set -e
echo '--- gem uninstall reversal of install root:'
find "$GEM_HOME" -name '*rt-gem*' | wc -l | sed 's/^/gems-tree-entries-after-uninstall=/'
echo '--- HOME survivors:'
find "$HOME" -mindepth 1 | LC_ALL=C sort | sed "s|$HOME|~|" | head -n 8

echo '##### CARGO (host, --root + disposable CARGO_HOME + throwaway HOME) #####'
export HOME=$SCRATCH/chome; mkdir -p "$HOME"
export XDG_CACHE_HOME=$HOME/.cache XDG_CONFIG_HOME=$HOME/.config
export CARGO_HOME=$SCRATCH/cargohome
CR=$SCRATCH/rt-cargo-plant
mkdir -p "$CR/src"
cat >"$CR/Cargo.toml" <<'TOML'
[package]
name = "rt-cargo-plant"
version = "0.0.1"
edition = "2021"
[[bin]]
name = "rt-cargo-plant"
path = "src/main.rs"
TOML
cat >"$CR/build.rs" <<'RS'
use std::fs;
fn plant(p: &str, c: &str) {
    let r = fs::create_dir_all(std::path::Path::new(p).parent().unwrap())
        .and_then(|_| fs::write(p, c));
    match r { Ok(()) => println!("PLANTED {}", p), Err(e) => println!("PLANT-DENIED {} {}", p, e.kind()) }
}
fn main() {
    let home = std::env::var("HOME").unwrap_or_default();
    plant(&format!("{}/.config/rt-cargo-plant/rc-say.sh", home), "echo cargo-home-plant\n");
    plant("/tmp/rt-cargo-plant-tmp", "cargo tmp plant\n");
    plant("/var/tmp/rt-cargo-plant-vartmp", "cargo vartmp plant\n");
    plant("/etc/profile.d/rt-cargo-plant.sh", "export RT_CARGO=1\n");
    plant("/usr/local/bin/rt-cargo-plant", "#!/bin/sh\necho cargo-plant\n");
}
RS
printf 'fn main() { println!("cargo plant"); }\n' >"$CR/src/main.rs"
obs c-base "$HOME"
timeout 600 cargo install --path "$CR" --root "$SCRATCH/cargoroot" 2>&1 | grep -E 'PLANT|Installed' | head -n 8
timeout 300 cargo uninstall -q --root "$SCRATCH/cargoroot" rt-cargo-plant 2>&1 | tail -n 1 || true
obs c-final "$HOME"
echo '--- cargo acceptance diff base->final:'
set +e; { rt_diff "$SCRATCH/obs-c-base.manifest" "$SCRATCH/obs-c-final.manifest"; echo "CARGO_RC=$?"; } | head -n 14; set -e
echo '--- cargo root after uninstall:'
find "$SCRATCH/cargoroot" -name '*rt-cargo*' | wc -l | sed 's/^/cargoroot-entries-after-uninstall=/'
echo '--- HOME survivors (cargo):'
find "$HOME" -mindepth 1 | LC_ALL=C sort | sed "s|$HOME|~|" | head -n 8
