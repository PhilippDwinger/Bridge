//! The Bridge 4 node program. Phase 1: prints its version only.

fn main() {
    println!(
        "Bridge 4 node {} (phase 1 scaffold, {})",
        env!("CARGO_PKG_VERSION"),
        bridge_node::COMPARTMENT
    );
}
