#[cfg(windows)]
fn main() {
    use std::env;
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-search=native={}/lib", manifest_dir);
}

#[cfg(not(windows))]
fn main(){}