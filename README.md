[![License](https://img.shields.io/badge/License-BSD--2--Clause-blue.svg)](https://opensource.org/licenses/BSD-2-Clause)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Travis CI](https://travis-ci.org/KizzyCode/asn1_der.svg?branch=master)](https://travis-ci.org/KizzyCode/asn1_der)
[![AppVeyor CI](https://ci.appveyor.com/api/projects/status/github/KizzyCode/asn1_der?svg=true)](https://ci.appveyor.com/project/KizzyCode/asn1-der)

asn1_der
========
Welcome to my `asn1_der`-crate 🎉


What this crate is:
-------------------
This crate helps you to DER-(de-)serialize various types. It provides some traits to convert between encoded data,
DER-objects and native types as well and implements them for some common types. If you build it with the
`derive`-feature (enabled by default), you can use `#[derive(Asn1Der)]` to derive the traits for your named structs.

The following types have built-in support:
 - `DerObject`: A generic DER-object-wrapper that can hold any object (`DerObject{ tag: u8, payload: Vec<u8> }`)
 - `()`: The ASN.1-NULL-type
 - `bool`: The ASN.1-BOOLEAN-type
 - `Vec<u8>`: The ASN.1-OctetString-type
 - `String`: The ASN.1-UTF8String-type
 - `u128`: The ASN.1-INTEGER-type (within `[0, 2^128)`)
 - `Vec<T>`: The ASN.1-SEQUENCE-type for any type `T` that implements `FromDerObject` and `IntoDerObject`

With the `derive`-feature you can automatically derive `FromDerObject` and `IntoDerObject`:
```rust
#[derive(Asn1Der)] // Now our struct supports all DER-conversion-traits
struct Address {
	street: String,
	house_number: u128,
	postal_code: u128,
	state: String,
	country: String
}

#[derive(Asn1Der)]
struct Customer {
	name: String,
	e_mail_address: String,
	postal_address: Address
}

// Serialization:
let mut serialized = vec![0u8; my_customer.serialized_len()];
my_customer.serialize(serialized.iter_mut()).unwrap();

// Deserialization (this returns our customer if the data is valid):
let my_customer = Customer::deserialize(serialized.iter()).unwrap();
```


Changes from 0.5.10 to 0.6.0
----------------------------
From 0.5.10 to 0.6.0 the library was nearly completely rewritten with a much more modular approach.

 - The library is now separated into two modules:
   - The `der` module which contains the generic DER implementation which is more stringent than the previous version
     and uses iterators instead of slices to avoid unexpected panics
   - The `types` module which defines the `FromDerObject` and `IntoDerObject` traits and already implements them for
     some native types

 - The tests are also separated into multiple files that map to the modules
 - The `asn1_der_impl!`-macro was replaced with a procedural derive macro in the `asn1_der_derive`-subcrate
 
If you are looking for the old version, you can find it
[here](https://github.com/KizzyCode/asn1_der/tree/0.5.10-Legacy) – however please note that the old version is
deprecated and may contain some serious issues.


Dependencies
------------
This depends on your selected features. If you use the `derive`-feature (enabled by default), the crate depends on the
[quote](https://crates.io/crates/quote) and [syn](https://crates.io/crates/syn) crates which are used in the procedural
macro implementation. 

If you don't use the `derive`-feature, this crate is dependency-less.


Long-Term Goals:
----------------
 - Create a C-interface to make this library usable from C-FFI-compatible languages