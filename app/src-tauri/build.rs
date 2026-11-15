fn main() {
    // Declared on every target: the code names these cfgs everywhere, only Windows sets them.
    for guard in &GUARDS {
        println!("cargo:rustc-check-cfg=cfg({})", guard.cfg32);
    }
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        println!("cargo:rerun-if-changed=src/taskbar.cpp");
        cc::Build::new().cpp(true).file("src/taskbar.cpp").compile("hydra_taskbar");
        println!("cargo:rerun-if-changed=src/taskbar.cpp");
        for lib in ["propsys", "shell32", "ole32", "uuid", "user32"] {
            println!("cargo:rustc-link-lib={lib}");
        }
        build_guards();
    }
    tauri_build::build();
    println!("cargo:rerun-if-changed=icons");

    // cargo test binaries do not get Tauri's manifest; without Common Controls v6 they
    // fail to start. Embed it for tests and leave the app binary to Tauri.
    #[cfg(all(target_os = "windows", target_env = "msvc"))]
    {
        let manifest = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("common-controls.manifest");
        println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
        println!("cargo:rustc-link-arg=/MANIFESTINPUT:{}", manifest.display());
        println!("cargo:rustc-link-arg-bins=/MANIFEST:NO");
        println!("cargo:rerun-if-changed={}", manifest.display());
    }
}

/// A DLL that Sandboxie loads into every process of a Hydra box (see `sandbox.rs`), built from
/// one C file in `src`.
struct Guard {
    /// File name under `src`.
    source: &'static str,
    /// Stem of the built DLLs: `hydra_<stem>.dll` and `hydra_<stem>32.dll`.
    stem: &'static str,
    /// Environment variables carrying the built paths to the crate.
    env64: &'static str,
    env32: &'static str,
    /// Config flag set when the 32-bit build succeeded.
    cfg32: &'static str,
}

const GUARDS: [Guard; 2] = [
    Guard {
        source: "dnsguard.c",
        stem: "dnsguard",
        env64: "HYDRA_DNSGUARD",
        env32: "HYDRA_DNSGUARD32",
        cfg32: "hydra_guard32",
    },
    Guard {
        source: "idguard.c",
        stem: "idguard",
        env64: "HYDRA_IDGUARD",
        env32: "HYDRA_IDGUARD32",
        cfg32: "hydra_idguard32",
    },
];

/// Builds the guard DLLs: the 64-bit one always, the 32-bit one when the x86 MSVC toolchain is
/// installed. 64-bit MSVC targets only; elsewhere the crate compiles with no guard at all.
///
/// Every guard is built the same way — `/MT` so it needs no runtime beyond kernel32, `/GS-`
/// because there is no CRT to call a handler, `/LD` for a DLL that other processes load.
fn build_guards() {
    let msvc_x64 = std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc")
        && std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("x86_64");
    for guard in &GUARDS {
        println!("cargo:rerun-if-changed=src/{}", guard.source);
    }
    if !msvc_x64 { return; }
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let src = std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("src");
    for guard in &GUARDS {
        build_guard(guard, &src.join(guard.source), &out);
    }
}

fn build_guard(guard: &Guard, source: &std::path::Path, out: &std::path::Path) {
    let compile = |compiler: cc::Tool, dir: &std::path::Path, dll: &std::path::Path| -> bool {
        let _ = std::fs::create_dir_all(dir);
        compiler.to_command().current_dir(dir)
            .args(["/nologo", "/O1", "/MT", "/GS-", "/W3", "/LD"])
            .arg(source)
            .arg(format!("/Fe{}", dll.display()))
            .args(["/link", "/NOLOGO", "kernel32.lib"])
            .status().map(|s| s.success()).unwrap_or(false)
    };
    let dll = out.join(format!("hydra_{}.dll", guard.stem));
    assert!(compile(cc::Build::new().get_compiler(), out, &dll), "building {} failed", guard.source);
    println!("cargo:rustc-env={}={}", guard.env64, dll.display());
    // 32-bit programs started in a box load the 32-bit guard. Without the x86 toolchain the
    // build still succeeds, and boxes fall back to 64-bit only (see `sandbox.rs`).
    let dll32 = out.join(format!("hydra_{}32.dll", guard.stem));
    let built = cc::Build::new().target("i686-pc-windows-msvc").try_get_compiler().ok()
        .is_some_and(|c| compile(c, &out.join(format!("{}32", guard.stem)), &dll32));
    if built {
        println!("cargo:rustc-cfg={}", guard.cfg32);
        println!("cargo:rustc-env={}={}", guard.env32, dll32.display());
    } else {
        // A release without the 32-bit guards would ship boxes in which every 32-bit program
        // reports the host's identifiers and is not held to the account's relay: refuse to
        // build one. Debug builds carry on so a machine without the x86 tools can still develop.
        assert!(
            std::env::var("PROFILE").as_deref() != Ok("release"),
            "x86 MSVC toolchain not found: release builds need the 32-bit sandbox guard ({}). Install the \
             \"MSVC x86\" build tools component.",
            guard.source
        );
        println!(
            "cargo:warning=x86 MSVC toolchain not found: the 32-bit sandbox guard ({}) was not built",
            guard.source
        );
    }
}
