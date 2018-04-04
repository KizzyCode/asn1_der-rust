use std;
use super::{ Error, Asn1DerError, DerObject, FromDerObject, IntoDerObject, FromDerEncoded, IntoDerEncoded, be_encode, be_decode };

impl FromDerObject for () {
	fn from_der_object(der_object: DerObject) -> Result<Self, Error<Asn1DerError>> {
		// Validate tag and extract payload
		if der_object.tag != 0x05 { throw_err!(Asn1DerError::InvalidTag) }
		if der_object.payload.len() != 0 { throw_err!(Asn1DerError::InvalidEncoding) }
		Ok(())
	}
}
impl FromDerObject for bool {
	fn from_der_object(der_object: DerObject) -> Result<Self, Error<Asn1DerError>> {
		// Validate tag and parse payload
		if der_object.tag != 0x01 { throw_err!(Asn1DerError::InvalidTag) }
		if der_object.payload.len() != 1 || ![0xff, 0x00].contains(&der_object.payload[0]) { throw_err!(Asn1DerError::InvalidEncoding) }
		Ok(der_object.payload[0] == 0xff)
	}
}
impl FromDerObject for Vec<u8> {
	fn from_der_object(der_object: DerObject) -> Result<Self, Error<Asn1DerError>> {
		// Validate tag and extract payload
		if der_object.tag != 0x04 { throw_err!(Asn1DerError::InvalidTag) }
		Ok(der_object.payload)
	}
}
impl FromDerObject for String {
	fn from_der_object(der_object: DerObject) -> Result<Self, Error<Asn1DerError>> {
		// Validate tag and extract payload
		if der_object.tag != 0x0c { throw_err!(Asn1DerError::InvalidTag) }
		if let Ok(string) = String::from_utf8(der_object.payload) { Ok(string) }
			else { throw_err!(Asn1DerError::InvalidEncoding) }
	}
}
impl FromDerObject for u64 {
	fn from_der_object(der_object: DerObject) -> Result<Self, Error<Asn1DerError>> {
		// Validate tag and encoding
		if der_object.tag != 0x02 { throw_err!(Asn1DerError::InvalidTag) }
			else if der_object.payload.len() == 0 { throw_err!(Asn1DerError::InvalidEncoding) }
		
		// The leading byte only indicates that the number is unsigned and can be skipped
		let to_skip = if der_object.payload[0] == 0x00 { 1 } else { 0 };
		
		// Check that the number is not too large or signed and decode it
		if der_object.payload.len() - to_skip > std::mem::size_of::<u64>() || der_object.payload[0] & 0x80 != 0 { throw_err!(Asn1DerError::Unsupported, "Only integers [0, 2^64) are supported") }
		Ok(be_decode(&der_object.payload[to_skip ..]))
	}
}
impl FromDerObject for Vec<DerObject> {
	fn from_der_object(der_object: DerObject) -> Result<Self, Error<Asn1DerError>> {
		// Validate tag
		if der_object.tag != 0x30 { throw_err!(Asn1DerError::InvalidTag) }
		
		// Decode sub-objects
		let (mut der_objects, mut position) = (Vec::new(), 0);
		while position < der_object.payload.len() {
			// Decode element at `position`
			let decoded = DerObject::with_der_encoded(&der_object.payload[position ..])?;
			position += decoded.encoded_length();
			der_objects.push(decoded)
		}
		Ok(der_objects)
	}
}
impl<T> FromDerObject for Vec<T> where T: FromDerObject {
	fn from_der_object(der_object: DerObject) -> Result<Self, Error<Asn1DerError>> {
		let (mut objects, mut position) = (Vec::new(), 0);
		while position < der_object.payload.len() {
			// Decode element at `position`
			let decoded = DerObject::with_der_encoded(&der_object.payload[position ..])?;
			position += decoded.encoded_length();
			
			// Convert element
			let converted = T::from_der_object(decoded)?;
			objects.push(converted)
		}
		Ok(objects)
	}
}


impl IntoDerObject for () {
	fn into_der_object(self) -> DerObject {
		DerObject::new(0x05, Vec::new())
	}
}
impl IntoDerObject for bool {
	fn into_der_object(self) -> DerObject {
		DerObject::new(0x01, if self { vec![0xff] } else { vec![0x00] })
	}
}
impl IntoDerObject for Vec<u8> {
	fn into_der_object(self) -> DerObject {
		DerObject::new(0x04, self)
	}
}
impl IntoDerObject for String {
	fn into_der_object(self) -> DerObject {
		DerObject::new(0x0c, self.into())
	}
}
impl IntoDerObject for u64 {
	fn into_der_object(self) -> DerObject {
		// Check if we need a leading zero-byte as unsigned-indicator
		let leading_zeros = if self > std::i64::MAX as u64 { 1usize } else { 0usize };
		// Compute the payload-size (must be at least one because even `0x00` is represented in one byte)
		let payload_length = std::cmp::max(std::mem::size_of::<u64>() - (self.leading_zeros() as usize / 8), 1);
		
		// Create payload and encode number
		let mut payload = vec![0u8; leading_zeros + payload_length];
		be_encode(&mut payload[leading_zeros ..], self);
		DerObject::new(0x02, payload)
	}
}
impl IntoDerObject for Vec<DerObject> {
	fn into_der_object(self) -> DerObject {
		let mut payload = Vec::with_capacity(self.iter().fold(0, |l, d| l + d.encoded_length()));
		for der_object in self { payload.append(&mut der_object.into_der_encoded()) }
		DerObject::new(0x30, payload)
	}
}
impl<T> IntoDerObject for Vec<T> where T: IntoDerObject {
	fn into_der_object(self) -> DerObject {
		let mut payload = Vec::new();
		for object in self { payload.append(&mut object.into_der_encoded()) }
		DerObject::new(0x30, payload)
	}
}