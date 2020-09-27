use std::env;
use std::io::{Error, ErrorKind};
use std::path::PathBuf;

fn main() {
    if cfg!(target_os = "windows") {
        let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
        println!("cargo:rustc-link-search=native={}/lib", manifest_dir);

        let mut res = winres::WindowsResource::new();
        res.set_manifest(
            r#"
            <assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
            <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
                <security>
                    <requestedPrivileges>
                        <requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
                    </requestedPrivileges>
                </security>
            </trustInfo>
            </assembly>
            "#,
        );
        res.compile().unwrap();
    }

    /*
    println!("cargo:rerun-if-changed=kcp/ikcp.h");
    let mut builder = bindgen::Builder::default();

    let target = env::var("TARGET").unwrap_or_default();

    // Some hacks needs to be made to make cross-compilation to android possible
    // NOTE: YOU DO NOT NEED TO MAKE STANDALONE TOOLCHAINS
    if target.contains("android") {
        let ndk_home = PathBuf::from(
            env::var("NDK_HOME")
                .expect("please specify NDK root by setting the NDK_HOME environment variable"),
        );
        let (ar_prefix, clang_prefix) = match target.as_str() {
            "armv7-linux-androideabi" => ("arm-linux-androideabi", "armv7a-linux-androideabi"),
            other => (other, other),
        };
        // For asm includes
        let include_path = ndk_home
            .join("sysroot/usr/include")
            .join(ar_prefix)
            .display()
            .to_string();
        // Extra arguments are needed to ensure that bindgen will generate the bindings for the
        // target instead of the host
        builder = builder
            .clang_arg("--sysroot")
            .clang_arg(ndk_home.join("sysroot").display().to_string())
            .clang_arg("-isystem")
            .clang_arg(include_path);
        // Directory containing binary executables of NDK toolchain
        let bin_dir = std::fs::read_dir(ndk_home.join("toolchains/llvm/prebuilt"))
            .and_then(|mut result| {
                result.next().ok_or_else(|| {
                    Error::new(
                        ErrorKind::NotFound,
                        "found nothing under prebuilt directory",
                    )
                })
            })
            .and_then(|result| result.map(|result| result.path().join("bin")))
            .expect("error finding NDK prebuilt toolchain");
        env::set_var(
            "TARGET_CC", // Tell the cc crate which compiler to use
            bin_dir.join(format!(
                "{}26-clang{}", // Default API level 26
                clang_prefix,
                if cfg!(windows) { ".cmd" } else { "" }
            )),
        );
        env::set_var(
            "TARGET_AR", // Tell the cc crate which archiver to use
            bin_dir.join(format!(
                "{}-ar{}",
                ar_prefix,
                if cfg!(windows) { ".exe" } else { "" }
            )),
        );
    }

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    builder
        .header("kcp/ikcp.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("error generating bindings")
        .write_to_file(out_path.join("bindings.rs"))
        .expect("couldn't write bindings");

    cc::Build::new().file("kcp/ikcp.c").compile("ikcp");
     */
}
