// Clean build script — R3a golden (T0 shape): every write target is confined
// to cargo's OUT_DIR / CARGO_TARGET_TMPDIR roots, direct or via a one-hop
// `let` binding whose right-hand side names those env vars.
use std::env;
use std::fs;
use std::path::Path;

fn main() {
    fs::write(
        Path::new(&env::var("OUT_DIR").expect("OUT_DIR is set by cargo")).join("generated.txt"),
        "generated under OUT_DIR only",
    )
    .unwrap();
    let staging = Path::new(&env::var("CARGO_TARGET_TMPDIR").unwrap_or_else(|_| env::var("OUT_DIR").expect("OUT_DIR"))).join("probe");
    fs::write(&staging, "one-hop TMPDIR/OUT_DIR binding").ok();
    println!("cargo:rerun-if-changed=build.rs");
}
