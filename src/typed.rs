use std;

/// An ASN.1-OctetString-object; used to store arbitrary byte-aligned data
#[derive(PartialEq, Eq, Debug, Default, Clone)]
pub struct OctetString {
	pub data: Vec<u8>
}
impl From<super::Generic> for Result<OctetString, super::Error> {
	/// Transforms a [`Generic`](../struct.Generic.html) into an `OctetString`
	///
	/// Returns [`Error::InvalidTag`](../enum.Error.html) if the generic has an invalid ASN.1-tag
	fn from(generic: super::Generic) -> Self {
		// Validate tag
		if generic.tag != 0x04 { return Err(super::Error::InvalidTag) }
		
		Ok(OctetString{ data: generic.payload })
	}
}
impl From<OctetString> for super::Generic {
	fn from(typed: OctetString) -> Self {
		super::Generic{ tag: 0x04, payload: typed.data }
	}
}
impl From<OctetString> for Vec<u8> {
	fn from(typed: OctetString) -> Self {
		typed.data
	}
}
impl From<Vec<u8>> for OctetString {
	fn from(data: Vec<u8>) -> Self {
		OctetString{ data }
	}
}



/// An ASN.1-UTF8String-object; used to store an UTF-8-string
#[derive(PartialEq, Eq, Debug, Default, Clone)]
pub struct UTF8String {
	pub string: String
}
impl From<super::Generic> for Result<UTF8String, super::Error> {
	/// Transforms a [`Generic`](../struct.Generic.html) into an `OctetString`
	///
	/// Returns [`Error::InvalidTag`](../enum.Error.html) if the generic has an invalid ASN.1-tag or
	/// [`Error::InvalidEncoding`](../enum.Error.html) if the generic cannot be decoded
	fn from(generic: super::Generic) -> Self {
		// Validate tag
		if generic.tag != 0x0c { return Err(super::Error::InvalidTag) }
		
		Ok(UTF8String{ string: String::from_utf8(generic.payload)? })
	}
}
impl From<UTF8String> for super::Generic {
	fn from(typed: UTF8String) -> Self {
		super::Generic{ tag: 0x0c, payload: typed.string.into_bytes() }
	}
}
impl From<UTF8String> for String {
	fn from(typed: UTF8String) -> Self {
		typed.string
	}
}
impl From<String> for UTF8String {
	fn from(string: String) -> Self {
		UTF8String{ string }
	}
}



/// An ASN.1-Integer-object; used to store an integer
///
/// _Note: because the integer is stored in an `u64`, this object is limited to integers in range `[0, 2^64)`._
#[derive(PartialEq, Eq, Debug, Default, Clone)]
pub struct Integer {
	pub value: u64
}
impl From<super::Generic> for Result<Integer, super::Error> {
	/// Transforms a [`Generic`](../struct.Generic.html) into an `OctetString`
	///
	/// Returns [`Error::InvalidTag`](../enum.Error.html) if the generic has an invalid ASN.1-tag,
	/// [`Error::InvalidEncoding`](../enum.Error.html) if the generic cannot be decoded or
	/// [`Error::Unsupported`](../enum.Error.html) if the generic is a valid object but unsupported
	fn from(generic: super::Generic) -> Self {
		// Validate tag and encoding
		if generic.tag != 0x02 { return Err(super::Error::InvalidTag) }
			else if generic.payload.len() == 0 { return Err(super::Error::InvalidEncoding) }
		
		// The leading byte only indicates that the number is unsigned and can be skipped
		let to_skip = if generic.payload[0] == 0x00 { 1 } else { 0 };
		
		// Check that the number is not too large or signed
		if generic.payload.len() - to_skip > std::mem::size_of::<u64>() || generic.payload[0] & 0x80 != 0 { return Err(super::Error::Unsupported) }
		
		// Parse number
		let mut value = 0u64;
		for index in to_skip..generic.payload.len() {
			value <<= 8;
			value |= generic.payload[index] as u64;
		}
		
		Ok(Integer{ value })
	}
}
impl From<Integer> for super::Generic {
	fn from(mut typed: Integer) -> Self {
		// Check if we need a leading zero-byte as unsigned-indicator
		let to_skip = if typed.value > i64::max_value() as u64 { 1usize }
			else { 0usize };
		
		// Create payload
		let byte_count = std::mem::size_of::<u64>() - (typed.value.leading_zeros() as usize / 8);
		let mut payload = vec![0u8; to_skip + byte_count];
		
		// Encode value
		for index in (to_skip .. to_skip + byte_count).rev() {
			payload[index] = typed.value as u8;
			typed.value >>= 8;
		}
		
		super::Generic{ tag: 0x02, payload }
	}
}
impl From<Integer> for u64 {
	fn from(typed: Integer) -> Self {
		typed.value
	}
}
impl From<u64> for Integer {
	fn from(value: u64) -> Self {
		Integer{ value }
	}
}



/// An ASN.1-Sequence-object; used to bundle multiple objects in it
#[derive(PartialEq, Eq, Debug, Default, Clone)]
pub struct Sequence {
	pub elements: Vec<super::Generic>
}
impl Sequence {
	pub fn at(&self, index: usize) -> Result<super::Generic, super::Error> {
		if index < self.elements.len() { Ok(self.elements[index].clone()) }
			else { Err(super::Error::LengthMismatch) }
	}
}
impl From<super::Generic> for Result<Sequence, super::Error> {
	/// Transforms a [`Generic`](../struct.Generic.html) into an `OctetString`
	///
	/// Returns [`Error::InvalidTag`](../enum.Error.html) if the generic has an invalid ASN.1-tag,
	/// [`Error::InvalidEncoding`](../enum.Error.html) if the generic cannot be decoded or
	/// any error from [`Generic::from_der_encoded`](../struct.Generic.html)
	fn from(generic: super::Generic) -> Self {
		// Validate tag
		if generic.tag != 0x30 { return Err(super::Error::InvalidTag) }
		
		// Extract elements from payload
		let (mut elements, mut pos) = (Vec::<super::Generic>::new(), 0usize);
		while pos < generic.payload.len() {
			let element = super::Generic::from_der_encoded(generic.payload[pos ..].to_vec())?;
			pos += element.get_der_encoded_length();
			elements.push(element)
		}
		Ok(Sequence{ elements })
	}
}
impl From<Sequence> for super::Generic {
	fn from(typed: Sequence) -> Self {
		// Create payload-buffer
		let payload_length = typed.elements.iter().map(|e| e.get_der_encoded_length()).sum();
		let mut payload = Vec::<u8>::with_capacity(payload_length);
		
		// Encode elements
		for element in typed.elements { payload.append(&mut element.into_der_encoded()) }
		
		super::Generic{ tag: 0x30, payload }
	}
}
impl From<Sequence> for Vec<super::Generic> {
	fn from(typed: Sequence) -> Self {
		typed.elements
	}
}
impl From<Vec<super::Generic>> for Sequence {
	fn from(elements: Vec<super::Generic>) -> Self {
		Sequence{ elements }
	}
}