asn1_der
========
Welcome to my `asn1_der`-library :D


What this library is:
---------------------
This library provides a simple ASN.1-DER en-/decoder.
It provides generic support for any ASN.1-type as well as specialized objects for some types 
(currently `OctetString`, `UTF8String`, `Integer` within range `[0, 2^64)` and `Sequence`)


What This Library is Not:
-------------------------
This library is nothing advanced like an X.509-certificate decoder but rather a building-block to create something advanced.
It only provides some features for encoding, decoding and validating ASN.1-DER data.


Build Documentation and Library:
--------------------------------
To build the documentation, change into the projects root-directory and run `cargo doc --release`;
you can find the documentation at `target/doc/asn1_der/index.html`.

To build this library, change into the projects root-directory and run `cargo build --release`;
you can find the build in `target/release`.


Guarantees:
-----------
I do not provide any guarantees about anything regarding this library (see license).
However I tried to create extensive tests and because this library only uses `safe Rust`, you _should_ at least be safe
against memory-corruption issues like buffer-overflows etc.


Long-Term Goals:
----------------
 - Create a C-interface to make this library usable from C-FFI-compatible languages.
 - Add more specialized objects for ASN.1-types
 - Convert the specialized objects into protocol-extensions for their corresponding type