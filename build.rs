fn main() {
    // Compile the C core library and link it into the Rust binary.
    // The C tools (attack/, fake/, fuzz/) are still built separately via Makefile.
    cc::Build::new()
        .file("libty/thc-ipv6-lib.c")
        .include("libty")
        .flag_if_supported("-O3")
        .flag_if_supported("-flto")
        .flag_if_supported("-Wno-unused-result")
        // Mirror the Makefile's OpenSSL flag when the library is present.
        .define("_HAVE_SSL", None)
        .compile("ty_core");

    println!("cargo:rustc-link-lib=pcap");
    println!("cargo:rustc-link-lib=ssl");
    println!("cargo:rustc-link-lib=crypto");
    println!("cargo:rerun-if-changed=libty/thc-ipv6-lib.c");
    println!("cargo:rerun-if-changed=libty/thc-ipv6.h");
}
