//
// examples/verify.rs — Build the LACUNA chain and walk it
//
// Equivalent to:  lacuna.exe verify
//
// Run with:  cargo run --example verify --features stack-spoof
//

#[macro_use]
extern crate litcrypt2;
extern crate alloc;
use_litcrypt!();

#[cfg(not(feature = "stack-spoof"))]
fn main() {
    eprintln!("{}", lc!("verify requires the 'stack-spoof' feature:"));
    eprintln!("{}", lc!("  cargo run --example verify --features stack-spoof"));
}

#[cfg(feature = "stack-spoof")]
fn main() {
    println!("{}", lc!("LACUNA Chain — Ghost Frames: Forging Plausible Call Stacks from .pdata Lacunae"));
    println!("{}\n", lc!("Rust port — verify mode"));

    if !lacuna::chain::build_chain() {
        eprintln!("{}", lc!("[-] build_chain failed"));
        std::process::exit(1);
    }

    let _ok = lacuna::chain::walk_chain();
}
