//
// veh.rs — Vectored Exception Handler + hardware-breakpoint parameter
//          encryption for lacuna-rs
//
// The VEH fires on DR0 (set on syscall;ret). It decrypts params only.
// Return-address spoofing is handled by the stub's epilogue.
// No DR1, no full_spoof, no [RSP] modification.
//

#![cfg(feature = "veh")]
#![allow(dead_code)]

use crate::win::{
    LONG, PVOID,
    CONTEXT, EXCEPTION_POINTERS,
    EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH,
    EXCEPTION_SINGLE_STEP, CONTEXT_DEBUG_REGISTERS,
    CURRENT_THREAD, AddVectoredExceptionHandler, RemoveVectoredExceptionHandler,
    GetThreadContext, SetThreadContext,
};
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use crate::win::ULONG64;

pub struct ParamCryptCtx {
    pub key: AtomicU64,
    pub armed: AtomicBool,
    pub full_spoof: AtomicBool,
}

pub static G_PCRYPT: ParamCryptCtx = ParamCryptCtx {
    key: AtomicU64::new(0),
    armed: AtomicBool::new(false),
    full_spoof: AtomicBool::new(false),
};

/// Runtime verbose flag — set via `set_verbose(true)` to enable VEH
/// diagnostic output (stack dumps, register prints). Off by default.
pub static G_VERBOSE: AtomicBool = AtomicBool::new(false);

/// Enable or disable verbose VEH diagnostics at runtime.
pub fn set_verbose(on: bool) {
    G_VERBOSE.store(on, Ordering::Relaxed);
}

pub static G_RET_GADGET: AtomicU64 = AtomicU64::new(0);
pub static G_REAL_RET: AtomicU64 = AtomicU64::new(0);

pub const MAX_SPOOF: usize = 16;
pub static G_SAVED_SLOTS: [AtomicU64; MAX_SPOOF] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
];
pub static G_SAVED_IDX: [AtomicUsize; MAX_SPOOF] = [
    AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0),
    AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0),
    AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0),
    AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0),
];
pub static G_N_SPOOFED: AtomicUsize = AtomicUsize::new(0);
pub static G_SPOOF_RSP: AtomicU64 = AtomicU64::new(0);
pub static G_EXE_BASE: AtomicU64 = AtomicU64::new(0);
pub static G_EXE_END: AtomicU64 = AtomicU64::new(0);

pub const STOMP_DEPTH: usize = 4;
pub static G_STOMP_SLOTS: [AtomicU64; STOMP_DEPTH] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
];
pub static G_STOMP_PTRS: [AtomicU64; STOMP_DEPTH] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
];
pub static G_STOMP_SAVED: AtomicU64 = AtomicU64::new(0);
pub static G_SAVE_RSP: AtomicU64 = AtomicU64::new(0);

#[cfg(not(feature = "stack-spoof"))]
fn ghost_layers() -> [ULONG64; 4] { [0; 4] }

#[cfg(feature = "stack-spoof")]
fn ghost_layers() -> [ULONG64; 4] { crate::chain::ghost_layers() }

pub unsafe fn dump_stack_frame(ctx: &CONTEXT, label: &str) {
    if !G_VERBOSE.load(Ordering::Relaxed) { return; }
    let rsp = ctx.Rsp as *const u64;
    let exe_base = G_EXE_BASE.load(Ordering::Relaxed);
    let exe_end = G_EXE_END.load(Ordering::Relaxed);
    let gh = ghost_layers();
    eprintln!();
    eprintln!("  +-- {} ---", label);
    eprintln!("  | RIP = {:#018x}  RSP = {:#018x}", ctx.Rip, ctx.Rsp);
    eprintln!("  | RCX = {:#018x}  R10 = {:#018x}", ctx.Rcx, ctx.R10);
    eprintln!("  | RDX = {:#018x}  R8  = {:#018x}", ctx.Rdx, ctx.R8);
    eprintln!("  | R9  = {:#018x}  RBX = {:#018x}", ctx.R9, ctx.Rbx);
    eprintln!("  | DR0 = {:#018x}  DR1 = {:#018x}", ctx.Dr0, ctx.Dr1);
    eprintln!("  | DR6 = {:#018x}  DR7 = {:#018x}", ctx.Dr6, ctx.Dr7);
    eprintln!("  |");
    eprintln!("  | exe range:  {:#018x}-{:#018x}", exe_base, exe_end);
    if gh.iter().all(|&g| g != 0) {
        eprintln!("  | ghost layers: L1={:#018x} L2={:#018x} L3={:#018x} L4={:#018x}",
                  gh[0], gh[1], gh[2], gh[3]);
    } else {
        eprintln!("  | ghost layers: (not set)");
    }
    eprintln!("  |");
    eprintln!("  |  stack dump (RSP-relative):");
    for i in -2isize..16isize {
        let val = *rsp.offset(i);
        let note: &str = if i == 0 { "<= [RSP]" }
            else if val == 0 { "(null)" }
            else if val >= exe_base && val < exe_end { "EXE" }
            else { "" };
        eprintln!("  |  [{:+4}]  {:#018x}  {}", i, val, note);
    }
    eprintln!("  +{}+", "-".repeat(40));
    eprintln!();
}

pub extern "system" fn param_encrypt_veh(ep: *mut EXCEPTION_POINTERS) -> LONG {
    unsafe {
        let rec = &*(*ep).ExceptionRecord;
        if rec.ExceptionCode != EXCEPTION_SINGLE_STEP as i32 {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        let ctx = &mut *(*ep).ContextRecord;
        if ctx.Dr6 & 0x1 == 0 || !G_PCRYPT.armed.load(Ordering::Relaxed) {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        let key = G_PCRYPT.key.load(Ordering::Relaxed);
        let verbose = G_VERBOSE.load(Ordering::Relaxed);
        if verbose {
            eprintln!("{}{:#x}", lc!("[veh] DR0 hit -- at syscall;ret  key="), key);
        }
        dump_stack_frame(ctx, "DR0: pre-syscall decrypt");
        if key != 0 {
            ctx.Rcx ^= key;
            ctx.R10 ^= key;
            ctx.Rdx ^= key;
            ctx.R8 ^= key;
            ctx.R9 ^= key;
            if verbose {
                eprintln!("{}RCX={:#018x} R10={:#018x} RDX={:#018x} R8={:#018x} R9={:#018x}",
                          lc!("[veh] decrypted: "),
                          ctx.Rcx, ctx.R10, ctx.Rdx, ctx.R8, ctx.R9);
            }
        }
        ctx.Dr0 = 0;
        ctx.Dr7 &= !0x1;
        ctx.Dr6 = 0;
        G_PCRYPT.armed.store(false, Ordering::Relaxed);
        if verbose {
            eprintln!("{}", lc!("[veh] DR0 cleared, continuing"));
        }
        EXCEPTION_CONTINUE_EXECUTION
    }
}

pub extern "system" fn chain_veh(ep: *mut EXCEPTION_POINTERS) -> LONG {
    unsafe {
        let ctx = &mut *(*ep).ContextRecord;
        let ip = ctx.Rip;
        let gh = ghost_layers();
        let in_chain = gh.iter().any(|&g| ip >= g.saturating_sub(16) && ip <= g + 16);
        if in_chain {
            if G_VERBOSE.load(Ordering::Relaxed) {
                eprintln!("{}{:#018x}{}", lc!("[veh] chain_veh: RIP "), ip, lc!(" inside ghost frame"));
            }
            #[cfg(feature = "stack-spoof")]
            { crate::chain::stomp_restore(); }
            ctx.Rsp = G_SAVE_RSP.load(Ordering::Relaxed);
            ctx.Rip = G_STOMP_SAVED.load(Ordering::Relaxed);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        EXCEPTION_CONTINUE_SEARCH
    }
}

pub fn pcrypt_arm(key: u64, syscall_ret_addr: u64, full: bool) {
    if syscall_ret_addr == 0 { return; }
    G_PCRYPT.key.store(key, Ordering::Relaxed);
    G_PCRYPT.armed.store(true, Ordering::Relaxed);
    G_PCRYPT.full_spoof.store(full, Ordering::Relaxed);
    unsafe {
        let mut ctx: CONTEXT = core::mem::zeroed();
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        GetThreadContext(CURRENT_THREAD, &mut ctx);
        ctx.Dr0 = syscall_ret_addr;
        ctx.Dr7 = (ctx.Dr7 & !0xF) | 0x1;
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        SetThreadContext(CURRENT_THREAD, &mut ctx);
    }
}

pub fn pcrypt_disarm() {
    G_PCRYPT.armed.store(false, Ordering::Relaxed);
    unsafe {
        let mut ctx: CONTEXT = core::mem::zeroed();
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        GetThreadContext(CURRENT_THREAD, &mut ctx);
        ctx.Dr0 = 0;
        ctx.Dr1 = 0;
        ctx.Dr7 &= !0x5;
        ctx.Dr6 = 0;
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        SetThreadContext(CURRENT_THREAD, &mut ctx);
    }
}

pub struct PcryptVehGuard { handle: PVOID }
impl PcryptVehGuard {
    pub fn register() -> Option<Self> {
        unsafe {
            let h = AddVectoredExceptionHandler(1, param_encrypt_veh);
            if h.is_null() { return None; }
            Some(PcryptVehGuard { handle: h })
        }
    }
}
impl Drop for PcryptVehGuard {
    fn drop(&mut self) {
        if !self.handle.is_null() { unsafe { RemoveVectoredExceptionHandler(self.handle); } }
    }
}

pub struct ChainVehGuard { handle: PVOID }
impl ChainVehGuard {
    pub fn register() -> Option<Self> {
        unsafe {
            let h = AddVectoredExceptionHandler(1, chain_veh);
            if h.is_null() { return None; }
            Some(ChainVehGuard { handle: h })
        }
    }
}
impl Drop for ChainVehGuard {
    fn drop(&mut self) {
        if !self.handle.is_null() { unsafe { RemoveVectoredExceptionHandler(self.handle); } }
    }
}

pub struct VehGuard {
    pcrypt: Option<PcryptVehGuard>,
    chain: Option<ChainVehGuard>,
}
impl VehGuard {
    pub fn register() -> Option<Self> {
        let pcrypt = PcryptVehGuard::register()?;
        Some(VehGuard { pcrypt: Some(pcrypt), chain: None })
    }
    pub fn register_chain(&mut self) { self.chain = ChainVehGuard::register(); }
}