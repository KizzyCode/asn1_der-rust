asn1_der
========
Welcome to my `asn1_der`-library 🎉


What this library is:
---------------------
This library provides a simple ASN.1-DER en-/decoder.
It provides generic support for any ASN.1-type as well as conversion-traits for some native types (currently
`OctetString <-> Vec<u8>`, `UTF8String <-> String`, `Integer <-> u64` and `Sequence <-> Vec<DerObject>`).


Build Documentation and Library:
--------------------------------
To build and open the documentation, go into the project's root-directory and run `cargo doc --release --open`

To build this library, change into the projects root-directory and run `cargo build --release`; you can find the build
in `target/release`.


Guarantees:
-----------
I do not provide any guarantees about anything regarding this library (see license).
However I tried to create extensive tests and because this library only uses `safe Rust` so you _should_ at least be
safe against memory-corruption issues like buffer-overflows etc.


Long-Term Goals:
----------------
 - Create a C-interface to make this library usable from C-FFI-compatible languages