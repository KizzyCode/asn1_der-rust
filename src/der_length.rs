use std;

/// Decode an ASN.1-DER-encoded length
///
/// The slice must begin at the first length-byte.
///
/// Returns `(decoded_length, number_of_length_bytes)` on success or
/// `Error::InvalidEncoding` if the length is invalid or
/// `Error::LengthMismatch` if the length-field is too short or
/// `Error::Unsupported` if the length is greater than [std::usize::MAX](https://doc.rust-lang.org/std/usize/constant.MAX.html).
pub fn decode(length_bytes: &[u8]) -> Result<(usize, usize), super::Error> {
	// Validate first length-byte
	if length_bytes.len() < 1 { return Err(super::Error::LengthMismatch) }
	let (mut length, mut byte_count) = (length_bytes[0] as usize, 1usize);
	
	// Check for multi-byte-length
	if length > 0x7f {
		// Get and validate byte-count
		byte_count = (length & 0x7f) + 1;
		if byte_count - 1 > std::mem::size_of::<usize>() { return Err(super::Error::Unsupported) }
		if byte_count > length_bytes.len() { return Err(super::Error::LengthMismatch) }
		
		// Decode and validate length (we must not use multi-byte-encoding for lengths smaller than 128)
		length = 0;
		for index in 1 .. byte_count {
			length <<= 8;
			length |= length_bytes[index] as usize;
		}
		if length < 0x80 { return Err(super::Error::InvalidEncoding) }
	}
	
	Ok((length, byte_count))
}


/// Computes the number of length-bytes for `length` in DER-representation without encoding it
pub fn get_encoded_length(length: usize) -> usize {
	if length > 0x7f { (std::mem::size_of::<usize>() - (length.leading_zeros() / 8) as usize) + 1 }
		else { 1 }
}

/// DER-encodes `length`
///
/// The slice must begin directly after the tag-byte.
pub fn encode(mut length: usize, buffer: &mut[u8]) {
	// Get encoded-length-size
	let byte_count = get_encoded_length(length);
	buffer[0] = length as u8;
	
	// Check for multi-byte-length
	if byte_count > 1 {
		// Multi-byte-length-indicator and byte-count
		buffer[0] = 0x80 | (byte_count - 1) as u8;
		
		// Encode length
		for index in (1..byte_count).rev() {
			buffer[index] = length as u8;
			length >>= 8;
		}
	}
}