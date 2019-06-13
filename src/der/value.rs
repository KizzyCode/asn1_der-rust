use ::Asn1DerError;


/// A wrapper around a DER value
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DerValue {
	/// The value
	pub data: Vec<u8>
}
impl DerValue {
	/// DER-deserializes the data from `source`
	pub fn deserialize<'a>(mut source: impl Iterator<Item = &'a u8>, len: impl Into<usize>)
		-> Result<Self, Asn1DerError>
	{
		// Create buffer and fill it with `len` bytes
		let mut data_buf = Vec::new();
		for _ in 0..len.into() {
			data_buf.push(*source.next().ok_or(Asn1DerError::LengthMismatch)?);
		}
		Ok(data_buf.into())
	}
	
	/// The length of the DER-serialized representation of `self`
	pub fn serialized_len(&self) -> usize {
		self.data.len()
	}
	/// DER-serializes `self` into `buf` and returns the amount of bytes written
	pub fn serialize<'a>(&self, mut buf: impl Iterator<Item = &'a mut u8>)
		-> Result<usize, Asn1DerError>
	{
		for b in self.data.iter() {
			*buf.next().ok_or(Asn1DerError::LengthMismatch)? = *b
		}
		Ok(self.data.len())
	}
	
	/// Efficiently computes the length of the DER-serialized representation of `payload_len` bytes
	pub fn compute_serialized_len(payload_len: usize) -> usize {
		payload_len
	}
}
impl From<Vec<u8>> for DerValue {
	fn from(data: Vec<u8>) -> Self {
		DerValue { data }
	}
}
impl From<DerValue> for Vec<u8> {
	fn from(value: DerValue) -> Self {
		value.data
	}
}