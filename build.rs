#[cfg(windows)]
fn add_packet_lib() {
    use std::env;
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-search=native={}/lib", manifest_dir);
}

#[cfg(not(windows))]
fn add_packet_lib() {}

fn main() {
    add_packet_lib();
}
