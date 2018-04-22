use std;
use super::{ Error, Asn1DerError, FromDerObject, IntoDerObject, FromDerEncoded, IntoDerEncoded, be_encode, be_decode };


/// Tries to decode the length of an DER-encoded object
///
/// This is especially useful if you don't have access to the full data yet (network-IO etc.)
/// and you want to know how long the payload is.
///
/// Parameters:
///  - `data`: The beginning of the DER-encoded stream
///
/// Returns:
///  - On success:
///     - `Some((total_length, payload_length))` if the length was decoded successfully
///     - `None` if there is not enough data available yet
///  - On error:
///     - `Asn1DerError::InvalidEncoding` if the length-field is invalid
///     - `Asn1DerError::Unsupported` if the length is greater than
///       [`std::usize::MAX`](https://doc.rust-lang.org/std/usize/constant.MAX.html)
pub fn try_decode_length(data: &[u8]) -> Result<Option<(usize, usize)>, Error<Asn1DerError>> {
	// Validate if we have at least one length-byte
	if data.len() < 2 { return Ok(None) }
	
	// Decode the length
	match decode_length(&data[1 ..]) {
		Ok((decoded_length, number_of_length_bytes)) => Ok(Some((1 + number_of_length_bytes + decoded_length, decoded_length))),
		Err(ref e) if e.kind == Asn1DerError::NotEnoughBytes => Ok(None),
		Err(e) => rethrow_err!(e)
	}
}

/// Decodes an ASN.1-DER-encoded length
///
/// Parameters:
///  - `length_bytes`: A slice over (but not limited to) the encoded length that begins with the
///    first length-byte
///
/// Returns:
///  - On success:
///     - `(payload_length, number_of_length_bytes)`
///  - On error:
///     - `Asn1DerError::InvalidEncoding` if the length-field is invalid
///     - `Asn1DerError::NotEnoughBytes` if the length-field is too short
///     - `Asn1DerError::Unsupported` if the length is greater than
///       [`std::usize::MAX`](https://doc.rust-lang.org/std/usize/constant.MAX.html)
pub fn decode_length(length_bytes: &[u8]) -> Result<(usize, usize), Error<Asn1DerError>> {
	// Validate first length-byte
	if length_bytes.len() < 1 { throw_err!(Asn1DerError::NotEnoughBytes) }
	let (mut length, mut byte_count) = (length_bytes[0] as usize, 1usize);
	
	// Check for multi-byte-length
	if length > 0x7f {
		// Get and validate byte-count
		byte_count += length & 0x7f;
		if byte_count - 1 > std::mem::size_of::<usize>() { throw_err!(Asn1DerError::Unsupported) }
		if byte_count > length_bytes.len() { throw_err!(Asn1DerError::NotEnoughBytes) }
		
		// Decode and validate length (we _must not_ allow multi-byte-encoding for lengths < 128)
		length = {
			let length = be_decode(&length_bytes[1 .. byte_count]);
			if length > std::usize::MAX as u64 { throw_err!(Asn1DerError::Unsupported) }
			if length < 0x80 { throw_err!(Asn1DerError::InvalidEncoding) }
			length as usize
		};
	}
	Ok((length, byte_count))
}

/// DER-encodes a length
///
/// Parameters:
///  - `length`: The length to DER-encode
///  - `buffer`: The buffer to write the encoded length into
pub fn encode_length(buffer: &mut[u8], length: usize) {
	// Get encoded-length-size
	let byte_count = length_field_size(length);
	buffer[0] = length as u8;
	
	// Check for multi-byte-length
	if byte_count > 1 {
		buffer[0] = 0x80 | (byte_count - 1) as u8;
		be_encode(&mut buffer[1 ..], length as u64);
	}
}

/// Computes the size an encoded length-field would have for a given payload-length
///
/// Parameters:
///  - `length`: The payload-length you want to know the encoded size of
///
/// Returns the size the encoded length-field would have
pub fn length_field_size(length: usize) -> usize {
	if length > 0x7f { (std::mem::size_of::<usize>() - (length.leading_zeros() / 8) as usize) + 1 }
		else { 1 }
}


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
	
	/// Computes the DER-encoded-length of this object without encoding it
	pub fn encoded_length(&self) -> usize {
		1 + length_field_size(self.payload.len()) + self.payload.len()
	}
}
impl FromDerObject for DerObject {
	fn from_der_object(der_object: DerObject) -> Result<Self, Error<Asn1DerError>> {
		Ok(der_object)
	}
}
impl IntoDerObject for DerObject {
	fn into_der_object(self) -> DerObject {
		self
	}
}
impl FromDerEncoded for DerObject {
	/// Create a `Generic`-object from DER-encoded data
	///
	/// Parameters:
	///  - `data`: The DER-encoded data to parse
	///
	/// Returns either the successfully parsed object or on error:
	///  - `Asn1DerError::NotEnoughBytes` if the overall length is zero, the length-field is too
	///    short or the payload is shorter than the annotated length
	///  - `Asn1DerError::InvalidEncoding` if the length-field is invalid
	///  - `Asn1DerError::Unsupported` if the length is greater than
	///    [`std::usize::MAX`](https://doc.rust-lang.org/std/usize/constant.MAX.html)
	fn from_der_encoded(mut data: Vec<u8>) -> Result<Self, Error<Asn1DerError>> {
		// Validate minimum-length
		if data.len() < 1 { throw_err!(Asn1DerError::NotEnoughBytes) }
		
		// Get `tag` and lengths and validate length
		let tag = data[0];
		let (payload_length, der_length_size) = try_err!(decode_length(&data[1 ..]));
		if 1 + der_length_size + payload_length > data.len() { throw_err!(Asn1DerError::NotEnoughBytes) }
		
		// Modify `data` to contain only the payload
		for i in 0 .. payload_length { data[i] = data[1 + der_length_size + i] } //memmove
		data.truncate(payload_length);
		
		Ok(DerObject::new(tag, data))
	}
	
	/// Create a `Generic`-object by decoding the DER-encoded data
	///
	/// _Warning: The resulting object will contain a __copy__ of the payload. However, the copying
	/// happens only if the object is valid and will be parsed and the copy includes __only__ the
	/// payload (and not any other remaining data)._
	///
	/// Parameters:
	///  - `data`: The DER-encoded data to parse; the data may be longer than the object
	///
	/// Returns either the successfully parsed object or on error:
	///  - `Asn1DerError::NotEnoughBytes` if the overall length is zero, the length-field is too
	///    short or the payload is shorter than the annotated length
	///  - `Asn1DerError::InvalidEncoding` if the length-field is invalid
	///  - `Asn1DerError::Unsupported` if the length is greater than
	///    [`std::usize::MAX`](https://doc.rust-lang.org/std/usize/constant.MAX.html)
	fn with_der_encoded(data: &[u8]) -> Result<Self, Error<Asn1DerError>> {
		// Validate minimum-length
		if data.len() < 1 { throw_err!(Asn1DerError::NotEnoughBytes) }
		
		// Decode and validate lengths
		let (payload_length, der_length_size) = try_err!(decode_length(&data[1 ..]));
		if 1 + der_length_size + payload_length > data.len() { throw_err!(Asn1DerError::NotEnoughBytes) }
		
		Ok(DerObject::new(data[0], data[1 + der_length_size .. 1 + der_length_size + payload_length].to_vec()))
	}
}
impl IntoDerEncoded for DerObject {
	/// DER-encodes this object
	fn into_der_encoded(mut self) -> Vec<u8> {
		// Compute/store lengths
		let (der_length_size, payload_length) = (length_field_size(self.payload.len()), self.payload.len());
		
		// Create and resize buffer and move payload to the back
		self.payload.resize(1 + der_length_size + payload_length, 0);
		for i in (0 .. payload_length).rev() { self.payload[1 + der_length_size + i] = self.payload[i] } //memmove
		
		// Set tag and encode length
		self.payload[0] = self.tag;
		encode_length(&mut self.payload[1 .. 1 + der_length_size], payload_length);
		
		self.payload
	}
}