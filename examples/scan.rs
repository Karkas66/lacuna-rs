//
// examples/scan.rs — Scan all target modules for ghost regions + gadgets
//
// Equivalent to:  lacuna.exe scan
//
// Run with:  cargo run --example scan
//

#[macro_use]
extern crate litcrypt2;
extern crate alloc;
use_litcrypt!();

use lacuna::{scan_all, scan, win::get_module};

fn main() {
    println!("{}", lc!("LACUNA Chain — Ghost Frames: Forging Plausible Call Stacks from .pdata Lacunae"));
    println!("{}\n", lc!("Rust port — scan mode"));

    let summary = scan_all();

    for m in &summary.modules {
        println!("{}{}{}{}", m.name, lc!("  —  "), m.ghost_count, lc!(" ghost regions"));

        // Re-scan to print details (scan_all only returns the count).
        let mut buf = [scan::Ghost {
            va_start: 0, va_end: 0, size: 0, export_va: 0, dist: 0, name: [0; 64],
        }; 512];

        let mod_name: &[u8] = if m.name.starts_with("ntdll") {
            b"ntdll.dll\0"
        } else if m.name.starts_with("kernelbase") {
            b"kernelbase.dll\0"
        } else if m.name.starts_with("wow64") {
            b"wow64.dll\0"
        } else {
            b"win32u.dll\0"
        };

        let h = get_module(mod_name);
        if h.is_null() {
            continue;
        }

        let targets: &[&[u8]] = match m.name.as_str() {
            "ntdll.dll" => &[
                b"NtAllocateVirtualMemory\0", b"NtCreateThreadEx\0",
                b"RtlCreateUserThread\0", b"LdrLoadDll\0", b"RtlUserThreadStart\0",
            ],
            "kernelbase.dll" => &[
                b"VirtualProtect\0", b"VirtualAllocEx\0",
                b"WriteProcessMemory\0", b"CreateRemoteThreadEx\0",
            ],
            "wow64.dll" => &[
                b"Wow64PrepareForException\0", b"Wow64KiUserCallbackDispatcher\0",
                b"Wow64ApcRoutine\0",
            ],
            _ => &[
                b"NtGdiDdDDICreateDevice\0", b"NtUserCallNoParam\0",
            ],
        };

        let n = scan::scan_ghosts(h, targets, &mut buf);
        for j in 0..n.min(25) {
            let g = &buf[j];
            let name = g.name.iter().take_while(|&&b| b != 0)
                .map(|&b| b as char).collect::<String>();
            println!(
                "{}{:016x}{}{:016x}{}{:4}{}{:30}{}{}",
                lc!("  "),
                g.va_start,
                lc!("–"),
                g.va_end,
                lc!("  "),
                g.size,
                lc!("B  "),
                if name.is_empty() { lc!("—") } else { name },
                lc!("  dist="),
                g.dist
            );
        }
        if n > 25 {
            println!("{}{}{}", lc!("  ... "), n - 25, lc!(" more"));
        }

        let mut gg = [scan::GhostGadget { va: 0, parent: [0; 64] }; 32];
        let ngg = scan::scan_ghost_gadgets(&buf[..n], mod_name, &mut gg);
        if ngg > 0 {
            println!("{}", lc!("  ghost gadgets (jmp [rbx]):"));
            for j in 0..ngg {
                println!("{}{:016x}", lc!("    "), gg[j].va);
            }
        }

        if m.name == "win32u.dll" {
            println!("{}{:016x}", lc!("  first nop gap: "), m.win32u_nop_gap);
        }

        println!();
    }
}