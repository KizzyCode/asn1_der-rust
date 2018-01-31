use std;
use super::{ Error, ErrorType };

/// A generic ASN.1-DER-object; can store any tag and payload
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct DerObject {
	pub tag: u8,
	pub payload: Vec<u8>
}
impl DerObject {
	/// Creates a new ASN.1-DER-object
	pub fn new(tag: u8, payload: Vec<u8>) -> Self {
		DerObject{ tag, payload }
	}
	
	/// Create a `Generic`-object from DER-encoded data
	///
	/// Returns either `Self` or
	/// [`Error::LengthMismatch`](enum.Error.html) if the overall length is zero, the length-field
	/// 	is too short or the payload-length does not match the annotated length,
	/// [`Error::InvalidEncoding`](enum.Error.html) if the length-field itself is invalid or
	/// [`Error::Unsupported`](enum.Error.html) if the length is greater than [`std::usize::MAX`](https://doc.rust-lang.org/std/usize/constant.MAX.html).
	pub fn from_encoded(mut data: Vec<u8>) -> Result<Self, Error> {
		// Validate minimum-length
		if data.len() < 1 { throw_err!(ErrorType::LengthMismatch) }
		
		// Get `tag` and lengths and validate length
		let tag = data[0];
		let (payload_length, der_length_size) = DerObject::decode_length(&data[1 ..])?; // Try to decode the length
		if 1 + der_length_size + payload_length > data.len() { throw_err!(ErrorType::LengthMismatch) }
		
		// Modify `data` to contain only the payload
		for i in 0 .. payload_length { data[i] = data[1 + der_length_size + i] } //memmove
		data.truncate(payload_length);
		
		Ok(DerObject::new(tag, data))
	}
	
	/// Create a `Generic`-object with DER-encoded data
	///
	/// Returns [`Error::LengthMismatch`](enum.Error.html) if the overall length is zero,
	/// 	the length-field is too short or the payload-length does not match the annotated length,
	/// [`Error::InvalidEncoding`](enum.Error.html) if the length-field itself is invalid or
	/// [`Error::Unsupported`](enum.Error.html) if the length is greater than [`std::usize::MAX`](https://doc.rust-lang.org/std/usize/constant.MAX.html).
	pub fn with_encoded(data: &[u8]) -> Result<Self, Error> {
		// Validate minimum-length
		if data.len() < 1 { throw_err!(ErrorType::LengthMismatch) }
		
		// Decode and validate lengths
		let (payload_length, der_length_size) = DerObject::decode_length(&data[1 ..])?; // Try to decode the length
		if 1 + der_length_size + payload_length > data.len() { throw_err!(ErrorType::LengthMismatch) }
		
		Ok(DerObject::new(data[0], data[1 + der_length_size .. 1 + der_length_size + payload_length].to_vec()))
	}
	
	/// Computes the length of this object in DER-encoded representation without encoding it
	pub fn encoded_length(&self) -> usize {
		1 + DerObject::encoded_length_size(self.payload.len()) + self.payload.len()
	}
	
	/// Transforms the object and returns a vector containing the DER-encoded object
	pub fn into_encoded(mut self) -> Vec<u8> {
		// Compute/store lengths
		let (der_length_size, payload_length) = (DerObject::encoded_length_size(self.payload.len()), self.payload.len());
		
		// Create and resize buffer and move payload to the back
		self.payload.resize(1 + der_length_size + payload_length, 0);
		for i in (0 .. payload_length).rev() { self.payload[1 + der_length_size + i] = self.payload[i] } //memmove
		
		// Set tag and encode length
		self.payload[0] = self.tag;
		DerObject::encode_length(payload_length, &mut self.payload[1 .. 1 + der_length_size]);
		
		self.payload
	}
	
	
	
	/// Decode an ASN.1-DER-encoded length
	///
	/// The slice must begin at the first length-byte.
	///
	/// Returns `(decoded_length, number_of_length_bytes)` on success or
	/// `Error::InvalidEncoding` if the length is invalid or
	/// `Error::LengthMismatch` if the length-field is too short or
	/// `Error::Unsupported` if the length is greater than [std::usize::MAX](https://doc.rust-lang.org/std/usize/constant.MAX.html).
	fn decode_length(length_bytes: &[u8]) -> Result<(usize, usize), super::Error> {
		// Validate first length-byte
		if length_bytes.len() < 1 { throw_err!(ErrorType::LengthMismatch) }
		let (mut length, mut byte_count) = (length_bytes[0] as usize, 1usize);
		
		// Check for multi-byte-length
		if length > 0x7f {
			// Get and validate byte-count
			byte_count = (length & 0x7f) + 1;
			if byte_count - 1 > std::mem::size_of::<usize>() { throw_err!(ErrorType::Unsupported) }
			if byte_count > length_bytes.len() { throw_err!(ErrorType::LengthMismatch) }
			
			// Decode and validate length (we must not use multi-byte-encoding for lengths smaller than 128)
			length = {
				let length = super::big_endian::decode(&length_bytes[1 .. byte_count]);
				if length > std::usize::MAX as u64 { throw_err!(ErrorType::Unsupported, format!("Lengths greater than {} are unsupported", std::usize::MAX)) }
					else { length as usize }
			};
			if length < 0x80 { throw_err!(ErrorType::InvalidEncoding) }
		}
		
		Ok((length, byte_count))
	}
	
	/// DER-encodes `length`
	///
	/// The slice must begin directly after the tag-byte.
	fn encode_length(length: usize, buffer: &mut[u8]) {
		// Get encoded-length-size
		let byte_count = DerObject::encoded_length_size(length);
		buffer[0] = length as u8;
		
		// Check for multi-byte-length
		if byte_count > 1 {
			buffer[0] = 0x80 | (byte_count - 1) as u8;
			super::big_endian::encode(&mut buffer[1 ..], length as u64);
		}
	}
	
	/// Computes the number of length-bytes for `length` in DER-representation without encoding it
	fn encoded_length_size(length: usize) -> usize {
		if length > 0x7f { (std::mem::size_of::<usize>() - (length.leading_zeros() / 8) as usize) + 1 }
			else { 1 }
	}
}