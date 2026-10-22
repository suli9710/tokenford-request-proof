fn main() {
    println!("cargo:rustc-check-cfg=cfg(tlsn_insecure)");
    for name in ["RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"] {
        println!("cargo:rerun-if-env-changed={name}");
        if std::env::var(name).unwrap_or_default().contains("tlsn_insecure") {
            panic!("Refusing TLSNotary's insecure ideal-VM configuration");
        }
    }
}
