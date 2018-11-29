//! This crate helps you to DER-(de-)serialize various types. It provides some traits to convert
//! between encoded data, DER-objects and native types as well and implements them for some common
//! types. If you build it with the `derive`-feature (enabled by default), you can use
//! `#[derive(Asn1Der)]` to derive the traits for your named structs.
//!
//! The following types have built-in support:
//!  - `DerObject`: A generic DER-object-wrapper that can hold any object
//!    (`DerObject{ tag: u8, payload: Vec<u8> }`)
//!  - `()`: The ASN.1-NULL-type
//!  - `bool`: The ASN.1-BOOLEAN-type
//!  - `Vec<u8>`: The ASN.1-OctetString-type
//!  - `String`: The ASN.1-UTF8String-type
//!  - `u128`: The ASN.1-INTEGER-type (within `[0, 2^128)`)
//!  - `Vec<T>`: The ASN.1-SEQUENCE-type for any type `T` that implements `FromDerObject` and
//!    `IntoDerObject`
//!
//! With the `derive`-feature you can automatically derive `FromDerObject` and `IntoDerObject`:
//! ```rust
//! #[macro_use] extern crate asn1_der;
//! # #[cfg(feature = "derive")]
//! # {
//! use ::asn1_der::{ FromDerObject, IntoDerObject };
//!
//! #[derive(Asn1Der, Default)] // Now our struct supports all DER-conversion-traits
//! struct Address {
//! 	street: String,
//! 	house_number: u128,
//! 	postal_code: u128,
//! 	state: String,
//! 	country: String
//! }
//!
//! #[derive(Asn1Der, Default)]
//! struct Customer {
//! 	name: String,
//! 	e_mail_address: String,
//! 	postal_address: Address
//! }
//!
//! let my_customer = Customer::default();
//!
//! // Serialization:
//! let mut serialized = vec![0u8; my_customer.serialized_len()];
//! my_customer.serialize(serialized.iter_mut()).unwrap();
//!
//! // Deserialization (this returns our customer if the data is valid):
//! let my_customer = Customer::deserialize(serialized.iter()).unwrap();
//! # }
//! ```


#[cfg(feature = "derive")]
#[allow(unused_imports)] #[macro_use] extern crate asn1_der_derive;

/// Contains a generic ASN.1-DER-object-implementation
mod der;
/// Implements some DER types and their conversion from/to native types
mod types;

pub use ::{
	der::{ DerObject, DerTag, DerLength, DerValue },
	types::{ FromDerObject, IntoDerObject, U128Ext }
};
#[cfg(feature = "derive")]
#[doc(hidden)] pub use asn1_der_derive::*;


/// An `asn1_der`-related error
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Asn1DerError {
	/// Not enough or too much bytes/objects/space left
	LengthMismatch,
	/// The serialized tag does not match the type
	InvalidTag,
	/// The encoding does not conform to the DER standard
	InvalidEncoding,
	/// The element is not supported by this implementation
	Unsupported
}
impl ::std::fmt::Display for Asn1DerError {
	fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
		write!(f, "{:#?}", self)
	}
}
impl ::std::error::Error for Asn1DerError {}