use std::fs;

fn main() {
    // Linker script — use absolute path so it works regardless of cargo's CWD.
    // This lives in build.rs rather than .cargo/config.toml to avoid duplication
    // when building from git worktrees nested inside the main repo (bug 0014).
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-arg=-T{}/linker.ld", manifest_dir);
    println!("cargo:rerun-if-changed=linker.ld");

    // Watch user_programs.S itself — if it changes, we need to re-scan .incbin paths.
    println!("cargo:rerun-if-changed=src/arch/user_programs.S");

    // Parse .incbin directives from user_programs.S and emit rerun-if-changed
    // for each embedded binary. This way new user programs are tracked automatically.
    let asm = fs::read_to_string("src/arch/user_programs.S")
        .expect("failed to read user_programs.S");
    for line in asm.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with(".incbin") {
            // .incbin "path/to/binary"
            if let Some(start) = trimmed.find('"') {
                if let Some(end) = trimmed[start + 1..].find('"') {
                    let path = &trimmed[start + 1..start + 1 + end];
                    // Paths in .incbin are relative to the repo root (one level up from kernel/)
                    println!("cargo:rerun-if-changed=../{}", path);
                }
            }
        }
    }
}
