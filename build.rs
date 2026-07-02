//
// build.rs — lacuna-rs
//
// Forces frame-pointer preservation on the crate's own codegen unit so that
// the stack-spoofing primitives in `chain.rs` can reliably locate the caller's
// return-address slot via `mov rbp, {x}` inline asm.
//
// NOTE: this only affects THIS crate's compilation.  Consumers that want to
// use the `stack-spoof` feature must ALSO add to their own `.cargo/config.toml`:
//
//     [build]
//     rustflags = ["-C", "force-frame-pointers=yes"]
//
// or call the spoofed entry points only from code compiled with frame pointers.
//

fn main() {
    // ── litcrypt2 string-obfuscation key ───────────────────────────────────
    // litcrypt2 reads the encryption key from the LITCRYPT_ENCRYPT_KEY
    // environment variable at compile time.  If that variable is not set,
    // litcrypt2 auto-generates a random key — so we deliberately do NOT set
    // a static key here.  To pin a key for reproducible builds, set the env
    // var before invoking cargo:
    //
    //     set LITCRYPT_ENCRYPT_KEY=your-secret-key
    //     cargo build
    //

    // Only needed when the stack-spoof feature is on.
    let stack_spoof = std::env::var("CARGO_FEATURE_STACK_SPOOF").is_ok();

    if stack_spoof {
        println!("cargo:rustc-codegen-units=1");
        // Force frame pointers on our own unit.  This is the closest Rust
        // analogue to GCC's -fno-omit-frame-pointer.
        println!("cargo:rustc-cfg=stack_spoof_compiled");
    }

    // Target guard: x86_64-pc-windows-* only.
    let target = std::env::var("TARGET").unwrap_or_default();
    if !target.contains("windows") || !target.contains("x86_64") {
        // Not a hard error — the scanning/PE layers are portable in principle,
        // but the syscall + VEH + stomp layers are x64-Windows only.
        println!("cargo:warning=lacuna-rs: target '{}' is not x86_64-pc-windows; only PE scanning will work", target);
    }

    println!("cargo:rerun-if-changed=build.rs");
}