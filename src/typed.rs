use std;
use super::{ Error, ErrorType };
use super::DerObject;

/// A trait to parse DER-elements into their corresponding native types
pub trait FromDer<T> where Self: std::marker::Sized {
	/// Tries to parse `element` into `Self`
	///
	/// Returns `Self` on success or
	/// `Error::LengthMismatch` if the length-field is invalid/does not match the data-length,
	/// `Error::InvalidEncoding` if the data is invalid encoded,
	/// `Error::Unsupported` if the DER-element is probably valid but not supported or
	/// `Error::InvalidTag` if the tag does not match the expected type
	fn from_der(element: T) -> Result<Self, Error>;
}

impl FromDer<DerObject> for Vec<u8> {
	fn from_der(der_object: DerObject) -> Result<Self, Error> {
		// Validate tag and extract payload
		if der_object.tag != 0x04 { throw_err!(ErrorType::InvalidTag) }
		Ok(der_object.payload)
	}
}
impl FromDer<DerObject> for String {
	fn from_der(der_object: DerObject) -> Result<Self, Error> {
		// Validate tag and extract payload
		if der_object.tag != 0x0c { throw_err!(ErrorType::InvalidTag) }
		if let Ok(string) = String::from_utf8(der_object.payload) { Ok(string) }
			else { throw_err!(ErrorType::InvalidEncoding) }
	}
}
impl FromDer<DerObject> for u64 {
	fn from_der(der_object: DerObject) -> Result<Self, Error> {
		// Validate tag and encoding
		if der_object.tag != 0x02 { throw_err!(ErrorType::InvalidTag) }
			else if der_object.payload.len() == 0 { throw_err!(ErrorType::InvalidEncoding) }
		
		// The leading byte only indicates that the number is unsigned and can be skipped
		let to_skip = if der_object.payload[0] == 0x00 { 1 } else { 0 };
		
		// Check that the number is not too large or signed and decode it
		if der_object.payload.len() - to_skip > std::mem::size_of::<u64>() || der_object.payload[0] & 0x80 != 0 { throw_err!(ErrorType::Unsupported, format!("Integers not in range [0, 2^64) are not supported")) }
		Ok(super::big_endian::decode(&der_object.payload[to_skip ..]))
	}
}
impl FromDer<DerObject> for Vec<DerObject> {
	fn from_der(der_object: DerObject) -> Result<Self, Error> {
		// Validate tag
		if der_object.tag != 0x30 { throw_err!(ErrorType::InvalidTag) }
		
		// Decode sub-objects
		let (mut der_objects, mut position) = (Vec::new(), 0);
		while position < der_object.payload.len() {
			// Decode element at `position`
			let decoded = DerObject::with_encoded(&der_object.payload[position ..])?;
			position += decoded.encoded_length();
			der_objects.push(decoded)
		}
		Ok(der_objects)
	}
}



impl From<Vec<u8>> for DerObject {
	fn from(octet_string: Vec<u8>) -> Self {
		DerObject::new(0x04, octet_string)
	}
}
impl From<DerObject> for Vec<u8> {
	fn from(der_object: DerObject) -> Self {
		Vec::<u8>::from_der(der_object).unwrap()
	}
}

impl From<String> for DerObject {
	fn from(utf8_string: String) -> Self {
		DerObject::new(0x0c, utf8_string.into_bytes())
	}
}
impl From<DerObject> for String {
	fn from(der_object: DerObject) -> Self {
		String::from_der(der_object).unwrap()
	}
}

impl From<u64> for DerObject {
	fn from(integer: u64) -> Self {
		// Check if we need a leading zero-byte as unsigned-indicator
		let to_skip = if integer > i64::max_value() as u64 { 1usize }
			else { 0usize };
		
		// Create payload
		let byte_count = std::mem::size_of::<u64>() - (integer.leading_zeros() as usize / 8);
		let mut payload = vec![0u8; to_skip + byte_count];
		
		// Encode value
		super::big_endian::encode(&mut payload[to_skip ..], integer);
		DerObject::new(0x02, payload)
	}
}
impl From<DerObject> for u64 {
	fn from(der_object: DerObject) -> Self {
		u64::from_der(der_object).unwrap()
	}
}

impl From<Vec<DerObject>> for DerObject {
	fn from(der_objects: Vec<DerObject>) -> Self {
		// Compute payload-length
		let mut payload_length = 0;
		for der_object in der_objects.iter() { payload_length += der_object.encoded_length() }
		
		// Encode payload
		let mut payload = Vec::with_capacity(payload_length);
		for der_object in der_objects { payload.append(&mut der_object.into_encoded()) }
		DerObject::new(0x30, payload)
	}
}
impl From<DerObject> for Vec<DerObject> {
	fn from(der_object: DerObject) -> Self {
		Vec::<DerObject>::from_der(der_object).unwrap()
	}
}