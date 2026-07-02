//
// win.rs — minimal Win32/NT FFI bindings for lacuna-rs
//
// We deliberately avoid pulling in the `windows`/`windows-sys` crates so the
// crate stays self-contained and compiles under `no_std` (alloc only).  Only
// the prototypes actually used by the ported C code are declared here.
//
// Ported from lacuna_chain.c (typedefs at top of file).
//

#![allow(non_camel_case_types, non_snake_case, dead_code)]

use core::ffi::c_void;

// ── Primitive aliases ────────────────────────────────────────────────────────

pub type HANDLE = *mut c_void;
pub type HMODULE = *mut c_void;
pub type NTSTATUS = i32;
pub type ACCESS_MASK = u32;
pub type ULONG_PTR = usize;
pub type SIZE_T = usize;
pub type DWORD = u32;
pub type WORD = u16;
pub type BYTE = u8;
pub type ULONG64 = u64;
pub type DWORD64 = u64;
pub type LONG = i32;
pub type WCHAR = u16;
pub type BOOLEAN = u8;
pub type LARGE_INTEGER = i64;
pub type PSTR = *mut u8;

pub const NULL: HANDLE = core::ptr::null_mut();

// ── NT success ───────────────────────────────────────────────────────────────

#[inline]
pub fn nt_ok(s: NTSTATUS) -> bool {
    s >= 0
}

// ── CLIENT_ID / OBJECT_ATTRIBUTES ────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct CLIENT_ID {
    pub UniqueProcess: HANDLE,
    pub UniqueThread: HANDLE,
}

// Minimal OBJECT_ATTRIBUTES — we only ever zero-init it.
#[repr(C)]
pub struct OBJECT_ATTRIBUTES {
    pub Length: ULONG,
    pub RootDirectory: HANDLE,
    pub ObjectName: *mut c_void, // PUNICODE_STRING — we always pass NULL
    pub Attributes: ULONG,
    pub SecurityDescriptor: *mut c_void,
    pub SecurityQualityOfService: *mut c_void,
}

impl Default for OBJECT_ATTRIBUTES {
    fn default() -> Self {
        Self {
            Length: core::mem::size_of::<OBJECT_ATTRIBUTES>() as ULONG,
            RootDirectory: core::ptr::null_mut(),
            ObjectName: core::ptr::null_mut(),
            Attributes: 0,
            SecurityDescriptor: core::ptr::null_mut(),
            SecurityQualityOfService: core::ptr::null_mut(),
        }
    }
}

pub type CID = CLIENT_ID;

// ── NT function pointer typedefs ─────────────────────────────────────────────

pub type PNtOpenProcess = extern "system" fn(
    PHANDLE,
    ACCESS_MASK,
    *mut OBJECT_ATTRIBUTES,
    *mut CLIENT_ID,
) -> NTSTATUS;

pub type PNtDelayExecution = extern "system" fn(BOOLEAN, *mut LARGE_INTEGER) -> NTSTATUS;
pub type PNtClose = extern "system" fn(HANDLE) -> NTSTATUS;

pub type PNtOpenThread = extern "system" fn(
    PHANDLE,
    ACCESS_MASK,
    *mut OBJECT_ATTRIBUTES,
    *mut CLIENT_ID,
) -> NTSTATUS;

pub type PNtQueueApcThread = extern "system" fn(
    HANDLE,
    PVOID,
    PVOID,
    PVOID,
    PVOID,
) -> NTSTATUS;

pub type PNtAlertThread = extern "system" fn(HANDLE) -> NTSTATUS;

pub type PNtCreateSection = extern "system" fn(
    PHANDLE,
    ACCESS_MASK,
    *mut OBJECT_ATTRIBUTES,
    *mut LARGE_INTEGER,
    ULONG,
    ULONG,
    HANDLE,
) -> NTSTATUS;

pub type PNtMapViewOfSection = extern "system" fn(
    HANDLE,
    HANDLE,
    *mut PVOID,
    ULONG_PTR,
    SIZE_T,
    *mut LARGE_INTEGER,
    *mut SIZE_T,
    ULONG,
    ULONG,
    ULONG,
) -> NTSTATUS;

pub type PNtUnmapViewOfSection = extern "system" fn(HANDLE, PVOID) -> NTSTATUS;

pub type PNtProtectVirtualMemory = extern "system" fn(
    HANDLE,
    *mut PVOID,
    *mut SIZE_T,
    ULONG,
    *mut ULONG,
) -> NTSTATUS;

pub type PNtQueryInformationThread = extern "system" fn(
    ThreadHandle: HANDLE,
    ThreadInformationClass: ULONG,
    ThreadInformation: PVOID,
    ThreadInformationLength: ULONG,
    ReturnLength: *mut ULONG,
) -> NTSTATUS;

// ── Unwind APIs (used by verify) ─────────────────────────────────────────────

#[repr(C)]
pub struct RUNTIME_FUNCTION {
    pub BeginAddress: DWORD,
    pub EndAddress: DWORD,
    pub UnwindData: DWORD,
}

pub type PRUNTIME_FUNCTION = *mut RUNTIME_FUNCTION;

#[repr(C)]
pub struct UNWIND_HISTORY_TABLE_ENTRY {
    pub ImageBase: DWORD64,
    pub FunctionEntry: PRUNTIME_FUNCTION,
}

#[repr(C)]
pub struct UNWIND_HISTORY_TABLE {
    pub Count: ULONG,
    pub LocalHint: BYTE,
    pub GlobalHint: BYTE,
    pub Search: BYTE,
    pub Once: BYTE,
    pub LowAddress: DWORD64,
    pub HighAddress: DWORD64,
    pub Entry: [UNWIND_HISTORY_TABLE_ENTRY; 12],
}

pub type PRtlLookupFunctionEntry = extern "system" fn(
    ControlPc: DWORD64,
    ImageBase: *mut DWORD64,
    HistoryTable: *mut UNWIND_HISTORY_TABLE,
) -> PRUNTIME_FUNCTION;

// RtlVirtualUnwind is variadic-ish in the SDK; we declare a concrete signature.
pub type PRtlVirtualUnwind = extern "system" fn(
    HandlerType: ULONG,
    ImageBase: DWORD64,
    ControlPc: DWORD64,
    FunctionEntry: PRUNTIME_FUNCTION,
    ContextRecord: *mut CONTEXT,
    HandlerData: *mut PVOID,
    EstablisherFrame: *mut DWORD64,
    ContextPointers: PVOID,
);

// ── CONTEXT (x64) ────────────────────────────────────────────────────────────

pub const CONTEXT_AMD64: DWORD = 0x0010_0000;
pub const CONTEXT_CONTROL: DWORD = CONTEXT_AMD64 | 0x0001;
pub const CONTEXT_INTEGER: DWORD = CONTEXT_AMD64 | 0x0002;
pub const CONTEXT_SEGMENTS: DWORD = CONTEXT_AMD64 | 0x0004;
pub const CONTEXT_FLOATING_POINT: DWORD = CONTEXT_AMD64 | 0x0008;
pub const CONTEXT_DEBUG_REGISTERS: DWORD = CONTEXT_AMD64 | 0x0010;
pub const CONTEXT_FULL: DWORD = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS;

#[repr(C, align(16))]
pub struct M128A {
    pub Low: u64,
    pub High: i64,
}

#[repr(C, align(16))]
pub struct CONTEXT {
    pub P1Home: DWORD64,
    pub P2Home: DWORD64,
    pub P3Home: DWORD64,
    pub P4Home: DWORD64,
    pub P5Home: DWORD64,
    pub P6Home: DWORD64,
    pub ContextFlags: DWORD,
    pub MxCsr: DWORD,
    pub SegCs: WORD,
    pub SegDs: WORD,
    pub SegEs: WORD,
    pub SegFs: WORD,
    pub SegGs: WORD,
    pub SegSs: WORD,
    pub EFlags: DWORD,
    pub Dr0: DWORD64,
    pub Dr1: DWORD64,
    pub Dr2: DWORD64,
    pub Dr3: DWORD64,
    pub Dr6: DWORD64,
    pub Dr7: DWORD64,
    pub Rax: DWORD64,
    pub Rcx: DWORD64,
    pub Rdx: DWORD64,
    pub Rbx: DWORD64,
    pub Rsp: DWORD64,
    pub Rbp: DWORD64,
    pub Rsi: DWORD64,
    pub Rdi: DWORD64,
    pub R8: DWORD64,
    pub R9: DWORD64,
    pub R10: DWORD64,
    pub R11: DWORD64,
    pub R12: DWORD64,
    pub R13: DWORD64,
    pub R14: DWORD64,
    pub R15: DWORD64,
    pub Rip: DWORD64,
    pub FltSave: [u8; 512],
    pub VectorRegister: [M128A; 26],
    pub VectorControl: DWORD64,
    pub DebugControl: DWORD64,
    pub LastBranchToRip: DWORD64,
    pub LastBranchFromRip: DWORD64,
    pub LastExceptionToRip: DWORD64,
    pub LastExceptionFromRip: DWORD64,
}

impl Default for CONTEXT {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

// ── EXCEPTION_RECORD / VEH ───────────────────────────────────────────────────

pub const EXCEPTION_CONTINUE_EXECUTION: LONG = -1;
pub const EXCEPTION_CONTINUE_SEARCH: LONG = 0;

pub const EXCEPTION_SINGLE_STEP: DWORD = 0x8000_0004;

#[repr(C)]
pub struct EXCEPTION_RECORD {
    pub ExceptionCode: LONG,
    pub ExceptionFlags: DWORD,
    pub ExceptionRecord: *mut EXCEPTION_RECORD,
    pub ExceptionAddress: PVOID,
    pub NumberParameters: DWORD,
    pub ExceptionInformation: [ULONG_PTR; 15],
}

#[repr(C)]
pub struct EXCEPTION_POINTERS {
    pub ExceptionRecord: *mut EXCEPTION_RECORD,
    pub ContextRecord: *mut CONTEXT,
}

pub type PVECTORED_EXCEPTION_HANDLER =
    extern "system" fn(*mut EXCEPTION_POINTERS) -> LONG;

// ── Memory protection / allocation constants ─────────────────────────────────

pub type PVOID = *mut c_void;
pub type PHANDLE = *mut HANDLE;
pub type PULONG = *mut ULONG;
pub type ULONG = u32;
pub type PSIZE_T = *mut SIZE_T;
pub type PLARGE_INTEGER = *mut LARGE_INTEGER;

pub const MEM_COMMIT: DWORD = 0x0000_1000;
pub const MEM_RESERVE: DWORD = 0x0000_2000;
pub const MEM_RELEASE: DWORD = 0x0000_8000;

pub const PAGE_NOACCESS: DWORD = 0x01;
pub const PAGE_READONLY: DWORD = 0x02;
pub const PAGE_READWRITE: DWORD = 0x04;
pub const PAGE_EXECUTE: DWORD = 0x10;
pub const PAGE_EXECUTE_READ: DWORD = 0x20;
pub const PAGE_EXECUTE_READWRITE: DWORD = 0x40;

pub const ViewUnmap: ULONG = 2;
pub const ViewShare: ULONG = 1;

pub const SECTION_ALL_ACCESS: ACCESS_MASK = 0x000F_001F;

pub const SEC_COMMIT: ULONG = 0x800_0000;

pub const THREAD_SET_CONTEXT: ACCESS_MASK = 0x0010;
pub const THREAD_ALERT: ACCESS_MASK = 0x0004;
pub const THREAD_QUERY_INFORMATION: ACCESS_MASK = 0x0040;

pub const PROCESS_VM_OPERATION: ACCESS_MASK = 0x0008;
pub const PROCESS_VM_READ: ACCESS_MASK = 0x0010;
pub const PROCESS_VM_WRITE: ACCESS_MASK = 0x0020;
pub const PROCESS_QUERY_INFORMATION: ACCESS_MASK = 0x0400;

// ── Toolhelp32 ───────────────────────────────────────────────────────────────

pub const TH32CS_SNAPTHREAD: DWORD = 0x0000_0004;
pub const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;

// ── Thread information classes (for NtQueryInformationThread) ─────────────────

pub const ThreadBasicInformation: ULONG = 0;
pub const ThreadTimes: ULONG = 1;
pub const ThreadCycleTime: ULONG = 23;
pub const ThreadSuspendCount: ULONG = 35;

pub type KAFFINITY = ULONG_PTR;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct KERNEL_USER_TIMES {
    pub CreateTime: DWORD64,
    pub ExitTime: DWORD64,
    pub KernelTime: DWORD64,
    pub UserTime: DWORD64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct THREAD_CYCLE_TIME_INFORMATION {
    pub AccumulatedCycles: DWORD64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct THREAD_BASIC_INFORMATION {
    pub ExitStatus: NTSTATUS,
    pub TebBaseAddress: PVOID,
    pub ClientId: CLIENT_ID,
    pub AffinityMask: KAFFINITY,
    pub Priority: LONG,
    pub BasePriority: LONG,
}

#[repr(C)]
pub struct THREADENTRY32 {
    pub dwSize: DWORD,
    pub cntUsage: DWORD,
    pub th32ThreadID: DWORD,
    pub th32OwnerProcessID: DWORD,
    pub tpBasePri: LONG,
    pub tpDeltaPri: LONG,
    pub dwFlags: DWORD,
}

// ── extern "system" kernel32/ntdll imports ───────────────────────────────────

type FARPROC = extern "system" fn() -> isize;

#[link(name = "kernel32")]
extern "system" {
    pub fn GetModuleHandleA(lpModuleName: *const u8) -> HMODULE;
    pub fn GetModuleHandleW(lpModuleName: *const u16) -> HMODULE;
    pub fn LoadLibraryA(lpLibFileName: *const u8) -> HMODULE;
    pub fn GetProcAddress(hModule: HMODULE, lpProcName: *const u8) -> Option<FARPROC>;
    pub fn VirtualAlloc(
        lpAddress: PVOID,
        dwSize: SIZE_T,
        flAllocationType: DWORD,
        flProtect: DWORD,
    ) -> PVOID;
    pub fn VirtualFree(lpAddress: PVOID, dwSize: SIZE_T, dwFreeType: DWORD) -> BOOL;
    pub fn VirtualProtect(
        lpAddress: PVOID,
        dwSize: SIZE_T,
        flNewProtect: DWORD,
        lpflOldProtect: *mut DWORD,
    ) -> BOOL;
    pub fn CloseHandle(hObject: HANDLE) -> BOOL;
    pub fn CreateToolhelp32Snapshot(
        dwFlags: DWORD,
        th32ProcessID: DWORD,
    ) -> HANDLE;
    pub fn Thread32First(hSnapshot: HANDLE, lpte: *mut THREADENTRY32) -> BOOL;
    pub fn Thread32Next(hSnapshot: HANDLE, lpte: *mut THREADENTRY32) -> BOOL;
    pub fn OpenThread(
        dwDesiredAccess: DWORD,
        bInheritHandle: BOOL,
        dwThreadId: DWORD,
    ) -> HANDLE;
    pub fn GetCurrentThread() -> HANDLE;
    pub fn GetCurrentProcess() -> HANDLE;
    pub fn GetThreadContext(hThread: HANDLE, lpContext: *mut CONTEXT) -> BOOL;
    pub fn SetThreadContext(hThread: HANDLE, lpContext: *mut CONTEXT) -> BOOL;
    pub fn AddVectoredExceptionHandler(
        First: ULONG,
        Handler: PVECTORED_EXCEPTION_HANDLER,
    ) -> PVOID;
    pub fn RemoveVectoredExceptionHandler(Handle: PVOID) -> ULONG;
    pub fn GetLastError() -> DWORD;
    pub fn SetConsoleOutputCP(wCodePageID: UINT) -> BOOL;
}

#[link(name = "ntdll")]
extern "system" {
    pub fn NtDelayExecution(Alertable: BOOLEAN, DelayInterval: *mut LARGE_INTEGER) -> NTSTATUS;
}

// ── Convenience helpers ──────────────────────────────────────────────────────

pub type BOOL = i32;
pub type UINT = u32;

/// Get a module handle by ASCII name (e.g. b"ntdll.dll\0").
pub fn get_module(name: &[u8]) -> HMODULE {
    unsafe { GetModuleHandleA(name.as_ptr()) }
}

/// Resolve an export by name from a loaded module.
pub fn get_proc(h: HMODULE, name: &[u8]) -> Option<*mut c_void> {
    unsafe {
        GetProcAddress(h, name.as_ptr()).map(|f| f as *mut c_void)
    }
}

/// Current pseudo-handle (-2 == current thread, -1 == current process).
pub const CURRENT_THREAD: HANDLE = -2isize as HANDLE;
pub const CURRENT_PROCESS: HANDLE = -1isize as HANDLE;