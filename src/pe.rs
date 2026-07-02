//
// pe.rs — PE parsing helpers for lacuna-rs
//
// Ported from lacuna_chain.c: pe_section(), pe_export().
//
// These operate on a loaded module base (HMODULE) and read the in-memory PE
// structures directly.  No file I/O, no allocations.
//

#![allow(dead_code)]

use crate::win::{HMODULE, ULONG, ULONG64, WORD, DWORD};


// ── PE structures (minimal subset) ───────────────────────────────────────────

#[repr(C)]
pub struct IMAGE_DOS_HEADER {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: i32,
}

#[repr(C)]
pub struct IMAGE_FILE_HEADER {
    pub Machine: WORD,
    pub NumberOfSections: WORD,
    pub TimeDateStamp: DWORD,
    pub PointerToSymbolTable: DWORD,
    pub NumberOfSymbols: DWORD,
    pub SizeOfOptionalHeader: WORD,
    pub Characteristics: WORD,
}

#[repr(C)]
pub struct IMAGE_DATA_DIRECTORY {
    pub VirtualAddress: DWORD,
    pub Size: DWORD,
}

pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;

#[repr(C)]
pub struct IMAGE_OPTIONAL_HEADER64 {
    pub Magic: WORD,
    pub MajorLinkerVersion: u8,
    pub MinorLinkerVersion: u8,
    pub SizeOfCode: DWORD,
    pub SizeOfInitializedData: DWORD,
    pub SizeOfUninitializedData: DWORD,
    pub AddressOfEntryPoint: DWORD,
    pub BaseOfCode: DWORD,
    pub ImageBase: u64,
    pub SectionAlignment: DWORD,
    pub FileAlignment: DWORD,
    pub MajorOperatingSystemVersion: WORD,
    pub MinorOperatingSystemVersion: WORD,
    pub MajorImageVersion: WORD,
    pub MinorImageVersion: WORD,
    pub MajorSubsystemVersion: WORD,
    pub MinorSubsystemVersion: WORD,
    pub Win32VersionValue: DWORD,
    pub SizeOfImage: DWORD,
    pub SizeOfHeaders: DWORD,
    pub CheckSum: DWORD,
    pub Subsystem: WORD,
    pub DllCharacteristics: WORD,
    pub SizeOfStackReserve: u64,
    pub SizeOfStackCommit: u64,
    pub SizeOfHeapReserve: u64,
    pub SizeOfHeapCommit: u64,
    pub LoaderFlags: DWORD,
    pub NumberOfRvaAndSizes: DWORD,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

#[repr(C)]
pub struct IMAGE_NT_HEADERS64 {
    pub Signature: DWORD,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}

#[repr(C)]
pub struct IMAGE_SECTION_HEADER {
    pub Name: [u8; 8],
    pub Misc: IMAGE_SECTION_MISC,
    pub VirtualAddress: DWORD,
    pub SizeOfRawData: DWORD,
    pub PointerToRawData: DWORD,
    pub PointerToRelocations: DWORD,
    pub PointerToLinenumbers: DWORD,
    pub NumberOfRelocations: WORD,
    pub NumberOfLinenumbers: WORD,
    pub Characteristics: DWORD,
}

#[repr(C)]
pub union IMAGE_SECTION_MISC {
    pub PhysicalAddress: DWORD,
    pub VirtualSize: DWORD,
}

#[repr(C)]
pub struct IMAGE_EXPORT_DIRECTORY {
    pub Characteristics: DWORD,
    pub TimeDateStamp: DWORD,
    pub MajorVersion: WORD,
    pub MinorVersion: WORD,
    pub Name: DWORD,
    pub Base: DWORD,
    pub NumberOfFunctions: DWORD,
    pub NumberOfNames: DWORD,
    pub AddressOfFunctions: DWORD,
    pub AddressOfNames: DWORD,
    pub AddressOfNameOrdinals: DWORD,
}

pub const IMAGE_SCN_MEM_EXECUTE: DWORD = 0x2000_0000;

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Cast a module base to a byte pointer.
#[inline]
fn base_bytes(mod_base: HMODULE) -> *const u8 {
    mod_base as *const u8
}

/// Read the DOS header from a module base.
#[inline]
pub unsafe fn dos_header(base: HMODULE) -> *const IMAGE_DOS_HEADER {
    base as *const IMAGE_DOS_HEADER
}

/// Read the NT headers from a module base.
#[inline]
pub unsafe fn nt_headers(base: HMODULE) -> *const IMAGE_NT_HEADERS64 {
    let b = base_bytes(base);
    let dos = dos_header(base);
    b.offset((*dos).e_lfanew as isize) as *const IMAGE_NT_HEADERS64
}

/// Pointer to the first section header.
#[inline]
pub unsafe fn first_section(nt: *const IMAGE_NT_HEADERS64) -> *const IMAGE_SECTION_HEADER {
    let optional_end = (&(*nt).OptionalHeader) as *const _ as *const u8;
    let opt_size = core::mem::size_of::<IMAGE_OPTIONAL_HEADER64>();
    optional_end.add(opt_size) as *const IMAGE_SECTION_HEADER
    // NOTE: this is equivalent to IMAGE_FIRST_SECTION(nt) — the section table
    // immediately follows the optional header.
}

// ── Public API (ported from C) ───────────────────────────────────────────────

/// Find a section by 8-byte name.  Returns (virtual_address, virtual_size)
/// relative to the module base, or None.
///
/// Ported from pe_section().
pub fn section(mod_base: HMODULE, name: &[u8]) -> Option<(ULONG64, ULONG)> {
    unsafe {
        let b = base_bytes(mod_base);
        let nt = nt_headers(mod_base);
        let mut s = first_section(nt);
        for _ in 0..(*nt).FileHeader.NumberOfSections {
            let sec_name = &(*s).Name;
            // Compare up to 8 bytes; name may or may not be NUL-terminated.
            let n = name.len().min(8);
            if sec_name[..n] == name[..n] {
                let va = b.add((*s).VirtualAddress as usize) as ULONG64;
                let sz = (*s).Misc.VirtualSize;
                return Some((va, sz));
            }
            s = s.add(1);
        }
    }
    None
}

/// Resolve an export by name.  Returns the absolute VA, or 0 if not found.
///
/// Ported from pe_export().
pub fn export_va(mod_base: HMODULE, fname: &[u8]) -> ULONG64 {
    unsafe {
        let b = base_bytes(mod_base);
        let nt = nt_headers(mod_base);
        let erva = (*nt).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if erva == 0 {
            return 0;
        }
        let ed = b.add(erva as usize) as *const IMAGE_EXPORT_DIRECTORY;
        let names = b.add((*ed).AddressOfNames as usize) as *const DWORD;
        let ords = b.add((*ed).AddressOfNameOrdinals as usize) as *const WORD;
        let funcs = b.add((*ed).AddressOfFunctions as usize) as *const DWORD;

        for i in 0..(*ed).NumberOfNames {
            let name_rva = *names.add(i as usize);
            let name_ptr = b.add(name_rva as usize);
            // strcmp equivalent: compare NUL-terminated C string
            if cstr_eq(name_ptr, fname) {
                let ord = *ords.add(i as usize) as usize;
                let func_rva = *funcs.add(ord);
                return b.add(func_rva as usize) as ULONG64;
            }
        }
    }
    0
}

/// Compare a NUL-terminated C string pointer against a Rust byte slice.
///
/// Equivalent to `strcmp((char*)p, fname) == 0` in the C original.
/// Callers pass slices like `b"NtOpenProcess\0"` — the trailing NUL is
/// expected and handled correctly.
unsafe fn cstr_eq(p: *const u8, s: &[u8]) -> bool {
    let mut i = 0;
    loop {
        let c = *p.add(i);
        if c == 0 {
            // C string ended — match if we are at/past end of s,
            // or s[i] is also NUL (callers pass b"NtOpenProcess\0").
            return i >= s.len() || s[i] == 0;
        }
        if i >= s.len() {
            return false;
        }
        if c != s[i] {
            return false;
        }
        i += 1;
    }
}

/// Return the image's executable section range (first section with
/// IMAGE_SCN_MEM_EXECUTE), as (start_va, end_va) absolute.
///
/// Used by the ghost scanner to bound gap searches to .text.
pub fn exec_range(mod_base: HMODULE) -> Option<(ULONG64, ULONG64)> {
    unsafe {
        let b = base_bytes(mod_base);
        let nt = nt_headers(mod_base);
        let mut s = first_section(nt);
        for _ in 0..(*nt).FileHeader.NumberOfSections {
            if (*s).Characteristics & IMAGE_SCN_MEM_EXECUTE != 0 {
                let start = b.add((*s).VirtualAddress as usize) as ULONG64;
                let end = start + (*s).Misc.VirtualSize as ULONG64;
                return Some((start, end));
            }
            s = s.add(1);
        }
    }
    None
}

/// SizeOfImage from the optional header — used to bound the "exe range"
/// scan in the parameter-encryption VEH.
pub fn size_of_image(mod_base: HMODULE) -> ULONG64 {
    unsafe { (*nt_headers(mod_base)).OptionalHeader.SizeOfImage as ULONG64 }
}