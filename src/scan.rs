//
// scan.rs — .pdata ghost-region and gadget scanning for lacuna-rs
//
// Ported from lacuna_chain.c:
//   scan_ghosts(), best_ghost(), win32u_nop_gap(), find_mf_target(),
//   scan_ghost_gadgets().
//
// A "ghost" is an executable code region with no .pdata RUNTIME_FUNCTION
// coverage.  RtlVirtualUnwind treats such addresses as leaf frames and
// simply does RSP += 8 to find the next return address — this is the
// primitive that makes the LACUNA chain walkable.
//

#![allow(dead_code)]

use crate::pe;
use crate::win::{HMODULE, ULONG64, UINT};
use crate::win::{DWORD, BYTE};

// ── Public data types ────────────────────────────────────────────────────────

/// A .pdata lacuna — executable code with no RUNTIME_FUNCTION coverage.
///
/// Ported from `Ghost` in lacuna_chain.c.
#[derive(Clone, Copy)]
pub struct Ghost {
    pub va_start: ULONG64,
    pub va_end: ULONG64,
    pub size: UINT,
    pub export_va: ULONG64,
    pub dist: UINT,
    pub name: [u8; 64],
}

impl Ghost {
    pub fn name_str(&self) -> &[u8] {
        let n = self.name.iter().position(|&b| b == 0).unwrap_or(self.name.len());
        &self.name[..n]
    }
}

/// A `JMP [RBX]` (`FF 23`) gadget found inside a ghost region.
///
/// Ported from `GhostGadget` in lacuna_chain.c.
#[derive(Clone, Copy)]
pub struct GhostGadget {
    pub va: ULONG64,
    pub parent: [u8; 64],
}

// ── RUNTIME_FUNCTION (alias of win::RUNTIME_FUNCTION) ────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Rf {
    pub Begin: DWORD,
    pub End: DWORD,
    pub Unwind: DWORD,
}

// ── Unwind info header + codes (for find_mf_target) ──────────────────────────

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct UH {
    pub VF: BYTE,
    pub Prolog: BYTE,
    pub Count: BYTE,
    pub Frame: BYTE,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct UC {
    pub Off: BYTE,
    pub Op: BYTE,
}

pub const UWOP_PUSH_MACHFRAME: u8 = 10;

// ── win32u 8-byte NOP signature ──────────────────────────────────────────────

pub const WIN32U_NOP8: [u8; 8] = [0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00];

// ── scan_ghosts ──────────────────────────────────────────────────────────────

/// Scan a module's .pdata for gaps between RUNTIME_FUNCTION entries that
/// contain real (non-padding) code.
///
/// For each gap, find the nearest target export and record the distance.
///
/// Ported from scan_ghosts().
pub fn scan_ghosts(
    mod_base: HMODULE,
    targets: &[&[u8]],
    out: &mut [Ghost],
) -> usize {
    // Locate .pdata.
    let (pdata_va, pdata_sz) = match pe::section(mod_base, b".pdata") {
        Some(x) => x,
        None => return 0,
    };

    // Resolve target export VAs.
    let mut tva: [ULONG64; 32] = [0; 32];
    let mut tname: [[u8; 64]; 32] = [[0; 64]; 32];
    let mut n_t = 0usize;
    for &t in targets {
        if n_t >= 32 {
            break;
        }
        let v = pe::export_va(mod_base, t);
        if v != 0 {
            tva[n_t] = v;
            let n = t.len().min(63);
            tname[n_t][..n].copy_from_slice(&t[..n]);
            n_t += 1;
        }
    }

    let rf = pdata_va as *const Rf;
    let count = pdata_sz as usize / core::mem::size_of::<Rf>();
    let img = mod_base as ULONG64;
    let mut prev: ULONG64 = 0;
    let mut found = 0usize;

    for i in 0..count {
        if found >= out.len() {
            break;
        }
        let cur = unsafe { &*rf.add(i) };
        if cur.Unwind == 0 {
            continue;
        }
        let begin = img + cur.Begin as ULONG64;
        let end = img + cur.End as ULONG64;
        if prev != 0 && begin > prev {
            let sz = (begin - prev) as UINT;
            let gp = prev as *const u8;
            let mut nonpad = 0u32;
            let lim = (sz as usize).min(512);
            for k in 0..lim {
                let b = unsafe { *gp.add(k) };
                if b != 0xCC && b != 0x00 && b != 0x90 {
                    nonpad += 1;
                }
            }
            if nonpad > 4 && sz >= 8 {
                // nearest target export
                let mut best = 0xFFFF_FFFFu32;
                let mut bi = -1i32;
                for j in 0..n_t {
                    let d = if tva[j] >= prev && tva[j] <= prev + sz as ULONG64 {
                        0
                    } else if tva[j] > prev + sz as ULONG64 {
                        (tva[j] - (prev + sz as ULONG64)) as u32
                    } else {
                        (prev - tva[j]) as u32
                    };
                    if d < best {
                        best = d;
                        bi = j as i32;
                    }
                }
                let g = &mut out[found];
                g.va_start = prev;
                g.va_end = prev + sz as ULONG64;
                g.size = sz;
                g.export_va = if bi >= 0 { tva[bi as usize] } else { 0 };
                g.dist = best;
                g.name = [0; 64];
                if bi >= 0 {
                    let n = tname[bi as usize].iter().position(|&b| b == 0).unwrap_or(63);
                    g.name[..n].copy_from_slice(&tname[bi as usize][..n]);
                }
                found += 1;
            }
        }
        prev = end;
    }
    found
}

// ── best_ghost ───────────────────────────────────────────────────────────────

/// Find the ghost with the smallest distance whose name matches `target`.
///
/// Ported from best_ghost().
pub fn best_ghost<'a>(ghosts: &'a [Ghost], target: &[u8]) -> Option<&'a Ghost> {
    let mut best: Option<&Ghost> = None;
    let mut bd = 0xFFFF_FFFFu32;
    for g in ghosts {
        if g.name_str() == target && g.dist < bd {
            bd = g.dist;
            best = Some(g);
        }
    }
    best
}

// ── win32u_nop_gap ───────────────────────────────────────────────────────────

/// Find the first 4–16 byte NOP/padding gap between .pdata entries in win32u.
///
/// Ported from win32u_nop_gap().
pub fn win32u_nop_gap(mod_base: HMODULE) -> ULONG64 {
    let (pdata_va, pdata_sz) = match pe::section(mod_base, b".pdata") {
        Some(x) => x,
        None => return 0,
    };
    let rf = pdata_va as *const Rf;
    let count = pdata_sz as usize / core::mem::size_of::<Rf>();
    let img = mod_base as ULONG64;
    let mut prev: ULONG64 = 0;
    for i in 0..count {
        let cur = unsafe { &*rf.add(i) };
        if cur.Unwind == 0 {
            continue;
        }
        let begin = img + cur.Begin as ULONG64;
        if prev != 0 && begin > prev {
            let gap = (begin - prev) as u32;
            if (4..=16).contains(&gap) {
                let gp = prev as *const u8;
                let ok = if gap == 8 {
                    let s = unsafe { core::slice::from_raw_parts(gp, 8) };
                    s == WIN32U_NOP8
                } else {
                    let mut all_pad = true;
                    for k in 0..gap {
                        let b = unsafe { *gp.add(k as usize) };
                        if b != 0x00 && b != 0xCC && b != 0x90 {
                            all_pad = false;
                            break;
                        }
                    }
                    all_pad
                };
                if ok {
                    return prev;
                }
            }
        }
        prev = img + cur.End as ULONG64;
    }
    0
}

// ── find_mf_target ───────────────────────────────────────────────────────────

/// Find a RUNTIME_FUNCTION whose unwind info contains UWOP_PUSH_MACHFRAME
/// at offset 0 — the BYOUD-MF anchor.  Falls back to
/// KiUserExceptionDispatcher+4.
///
/// Ported from find_mf_target().
pub fn find_mf_target(ntdll: HMODULE) -> ULONG64 {
    if let Some((pdata_va, pdata_sz)) = pe::section(ntdll, b".pdata") {
        let rf = pdata_va as *const Rf;
        let count = pdata_sz as usize / core::mem::size_of::<Rf>();
        let img = ntdll as ULONG64;
        for i in 0..count {
            let cur = unsafe { &*rf.add(i) };
            if cur.Unwind == 0 {
                continue;
            }
            let uh = (img + cur.Unwind as ULONG64) as *const UH;
            let codes = (uh as *const u8).wrapping_add(4) as *const UC;
            let cnt = unsafe { (*uh).Count };
            for j in 0..cnt as usize {
                let c = unsafe { &*codes.add(j) };
                if (c.Op & 0xF) == UWOP_PUSH_MACHFRAME && c.Off == 0 {
                    return img + cur.Begin as ULONG64 + 4;
                }
            }
        }
    }
    pe::export_va(ntdll, b"KiUserExceptionDispatcher\0") + 4
}

// ── scan_ghost_gadgets ───────────────────────────────────────────────────────

/// Scan ghost regions for `JMP [RBX]` (`FF 23`) instructions.
///
/// Ported from scan_ghost_gadgets().
pub fn scan_ghost_gadgets(
    ghosts: &[Ghost],
    mod_name: &[u8],
    out: &mut [GhostGadget],
) -> usize {
    let mut found = 0usize;
    'outer: for g in ghosts {
        let p = g.va_start as *const u8;
        let sz = g.size as usize;
        for k in 0..sz.saturating_sub(1) {
            let b0 = unsafe { *p.add(k) };
            let b1 = unsafe { *p.add(k + 1) };
            if b0 == 0xFF && b1 == 0x23 {
                let gg = &mut out[found];
                gg.va = g.va_start + k as ULONG64;
                gg.parent = [0; 64];
                let mn = mod_name.iter().position(|&b| b == 0).unwrap_or(mod_name.len());
                let _ = format_ghost_parent(&mut gg.parent, mod_name, mn, g.va_start);
                found += 1;
                if found >= out.len() {
                    break 'outer;
                }
            }
        }
    }
    found
}

/// Write `"{mod_name} ghost @{va:x}"` into a 64-byte buffer.
/// Returns the number of bytes written.
fn format_ghost_parent(buf: &mut [u8; 64], mod_name: &[u8], mn: usize, va: ULONG64) -> usize {
    let mut w = 0usize;
    // mod_name
    if w + mn < 64 {
        buf[w..w + mn].copy_from_slice(&mod_name[..mn]);
        w += mn;
    }
    // " ghost @"
    let suffix = b" ghost @";
    if w + suffix.len() < 64 {
        buf[w..w + suffix.len()].copy_from_slice(suffix);
        w += suffix.len();
    }
    // hex va
    let mut tmp = [0u8; 16];
    let hex_len = u64_to_hex(va, &mut tmp);
    if w + hex_len < 64 {
        buf[w..w + hex_len].copy_from_slice(&tmp[..hex_len]);
        w += hex_len;
    }
    w
}

/// Format a u64 as lowercase hex into `out`, returning the number of digits.
fn u64_to_hex(v: u64, out: &mut [u8; 16]) -> usize {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    if v == 0 {
        out[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 16];
    let mut n = 0usize;
    let mut x = v;
    while x != 0 {
        tmp[n] = HEX[(x & 0xF) as usize];
        x >>= 4;
        n += 1;
    }
    // reverse into out
    for i in 0..n {
        out[i] = tmp[n - 1 - i];
    }
    n
}