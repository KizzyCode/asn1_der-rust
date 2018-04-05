[![License](https://img.shields.io/badge/License-BSD%202--Clause-blue.svg)](https://opensource.org/licenses/BSD-2-Clause)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

asn1_der
========
Welcome to my `asn1_der`-library 🎉


What this library is:
---------------------
This library helps you to DER-en-/-decode various types. It provides some traits to convert between encoded data,
DER-objects and native types as well as some trait-implementations for common types. There is also a macro
(`asn1_der_impl!`) that helps you to implement the traits for your structs.  

The following types have built-in support:
 - `DerObject`: A generic DER-object-wrapper that can hold any object (`DerObject{ tag: u8, payload: Vec<u8> }`)
 - `()`: The ASN.1-NULL-type
 - `bool`: The ASN.1-BOOLEAN-type
 - `Vec<u8>`: The ASN.1-OctetString-type
 - `String`: The ASN.1-UTF8String-type
 - `u64`: The ASN.1-INTEGER-type (within `0..u64::MAX`)
 - `Vec<DerObject>`: The ASN.1-SEQUENCE-type
 - `Vec<T>`: The ASN.1-SEQUENCE-type for sequences that contain only one type `T` (e.g. `Vec<String>` for a sequence
   that contains only UTF8Strings)

The macro `asn1_der_impl!` helps you to "derive" the trait-implementations for your own structs; e.g.:
```rust
struct Address {
	street: String,
	house_number: u64,
	postal_code: u64,
	state: String,
	country: String
}
asn1_der_impl!(Address{ street, house_number, postal_code, state, country }); // Now our struct supports all DER-conversion-traits

struct Customer {
	name: String,
	e_mail_address: String,
	postal_address: Address
}
asn1_der_impl!(Customer{ name, e_mail_address, postal_address }); // Now this struct supports all DER-conversion-traits too! It's only necessary that all fields implement these traits

// Serialization:
let encoded = my_customer.into_der_encoded(); // This returns a vector containing the DER-encoded representation of this customer (a sequence containing the struct's fields)

// Parsing:
let my_customer = Customer::from_der_encoded(encoded).unwrap(); // This returns our customer (if the data is valid)
```


Dependencies
------------
Only my [`etrace`-crate](https://github.com/KizzyCode/etrace)


Build Documentation and Library:
--------------------------------
To build and open the documentation, go into the project's root-directory and run `cargo doc --release --open`

To build this library, change into the projects root-directory and run `cargo build --release`; you can find the build
in `target/release`.


Long-Term Goals:
----------------
 - Create a C-interface to make this library usable from C-FFI-compatible languages