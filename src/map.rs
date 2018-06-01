//! This module allows you to serialize/parse a `HashMap`
//!
//! This module is currently feature-gated because DER does not support maps by default and the
//! implementation is currently unstable because:
//!  - We need to find a DER-compatible representation that we can agree upon (currently a sequence
//!    with multiple key-value pairs)
//!  - One advantage of DER over other encoding standards is that each data-constellation has one
//!    (and _exactly_ one) representation; so it's not enough to just create and encode our
//!    key-value pairs – we also need to specify a consistent order for them.
//!
//! The current format for `n` key-value-pairs is build like this:
//! `SEQUENCE(key_1, value_1, key_2, value_2, key_3, value_3, ..., key_n, value_n)`
//!
//! The order is currently only specified for `String`s in the following precedence:
//!  1. Take the binary representation of the strings. The string with the first lower/smaller
//!     byte comes first.
//!  2. If one string is an exact substring from the other (from the beginning), the shorter string
//!     comes first.

use std;
use super::{ Result, Asn1DerError, DerObject, FromDerObject, IntoDerObject, FromDerEncoded, IntoDerEncoded };


/// This trait defines that a type has a constant well defined and predictable order
pub trait DerMapOrdered {
	/// Gets the ordering of `self` compared to `other`
	fn ordering(&self, other: &Self) -> std::cmp::Ordering;
}
impl DerMapOrdered for String {
	fn ordering(&self, other: &Self) -> std::cmp::Ordering {
		// Prepare vars
		let to_compare = std::cmp::min(self.len(), other.len());
		let (a, b) = (self.as_bytes(), other.as_bytes());
		
		// Compare bytes
		for i in 0..to_compare {
			if a[i] < b[i] { return std::cmp::Ordering::Less }
			else if a[i] > b[i] { return std::cmp::Ordering::Greater }
		}
		
		// If both arrays are (partial) equal, compare the length
		if self.len() < other.len() { std::cmp::Ordering::Less }
		else if self.len() > other.len() { std::cmp::Ordering::Greater }
		else { std::cmp::Ordering::Equal }
	}
}


/// This trait defines map-like behaviour and is implemented for `HashMap` and `BTreeMap` so that
/// they can be used interchangeably
pub trait Map {
	/// The type of the keys
	type Key;
	/// The type of the values
	type Value;
	
	/// Creates a new instance of the map
	fn new() -> Self;
	/// Returns an iterator over the map's keys
	fn keys<'a>(&'a self) -> Vec<&'a Self::Key>;
	/// Removes a value for a key
	///
	/// Returns either _the value_ or `None` if the key does not exist
	fn remove(&mut self, key: &Self::Key) -> Option<Self::Value>;
	/// Inserts a value for a key
	fn insert(&mut self, key: Self::Key, value: Self::Value);
}
macro_rules! map_impl {
    () => {
		type Key = K;
		type Value = V;
	
		fn new() -> Self {
			Self::new()
		}
		fn keys<'a>(&'a self) -> Vec<&'a Self::Key> {
			Self::keys(self).collect()
		}
		fn remove(&mut self, key: &Self::Key) -> Option<Self::Value> {
			Self::remove(self, key)
		}
		fn insert(&mut self, key: Self::Key, value: Self::Value) {
			Self::insert(self, key, value);
		}
    };
}
impl<K, V> Map for std::collections::HashMap<K, V> where K: Eq + std::hash::Hash { map_impl!(); }
impl<K, V> Map for std::collections::BTreeMap<K, V> where K: Ord + std::hash::Hash { map_impl!(); }


impl<M> FromDerObject for M where M: Map<Key=String>, M::Value: FromDerObject {
	fn from_der_object(der_object: DerObject) -> Result<Self> {
		// Parse DER-objects
		let der_objects: Vec<DerObject> = try_err!(Vec::from_der_object(der_object));
		if der_objects.len() % 2 != 0 { throw_err!(Asn1DerError::InvalidEncoding, "The sequence cannot be decoded as a map") }
		
		// Process elements pairwise
		let (mut der_objects, mut map) = (der_objects.into_iter(), Self::new());
		while let (Some(key), Some(value)) = (der_objects.next(), der_objects.next()) {
			// Decode and insert pair
			let key: M::Key = try_err!(M::Key::from_der_object(key));
			let value: M::Value = try_err!(M::Value::from_der_object(value));
			map.insert(key, value);
		}
		Ok(map)
	}
}
impl<M> FromDerEncoded for M where M: Map<Key=String>, M::Value: FromDerObject {
	fn from_der_encoded(data: Vec<u8>) -> Result<Self> {
		let der_object: DerObject = try_err!(DerObject::from_der_encoded(data));
		Ok(try_err!(Self::from_der_object(der_object)))
	}
	fn with_der_encoded(data: &[u8]) -> Result<Self> {
		let der_object: DerObject = try_err!(DerObject::with_der_encoded(data));
		Ok(try_err!(Self::from_der_object(der_object)))
	}
}


impl<M> IntoDerObject for M where M: Map<Key=String>, M::Value: IntoDerObject {
	fn into_der_object(mut self) -> DerObject {
		// Get and sort all keys
		let mut keys: Vec<String> = self.keys().iter().map(|k| k.to_string()).collect();
		keys.sort_unstable_by(DerMapOrdered::ordering);
		
		// Create an array with [key_1, value_1, key_2, value_2, key_3, value_3, ..., key_n, value_n]
		let mut elements = Vec::with_capacity(keys.len() * 2);
		keys.into_iter().for_each(|k| {
			let element = self.remove(&k).unwrap().into_der_object();
			elements.extend_from_slice(&[k.into_der_object(), element]);
		});
		
		elements.into_der_object()
	}
}
impl<M> IntoDerEncoded for M where M: Map<Key=String>, M::Value: IntoDerObject {
	fn into_der_encoded(self) -> Vec<u8> {
		self.into_der_object().into_der_encoded()
	}
}