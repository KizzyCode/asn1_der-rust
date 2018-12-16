use ::Asn1DerError;

mod tag;
mod length;
mod value;

pub use self::{ length::DerLength, tag::DerTag, value::DerValue};


/// A generic DER object
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DerObject {
	/// A DER tag that represents this object's type
	pub tag: DerTag,
	/// The DER object's payload
	pub value: DerValue
}
impl DerObject {
	/// Creates a new DER object from `tag` and `value` (the length is computed from `value`)
	pub fn new(tag: DerTag, value: DerValue) -> Self {
		Self{ tag, value }
	}
	/// Creates a new DER object from `tag` and `value` (the length is computed from `value`)
	///
	/// Parameters:
	///  - `tag`: The DER tag value that represents the object's type
	///  - `value`: The DER payload bytes that this object should carry
	pub fn from_raw(tag: u8, bytes: impl Into<Vec<u8>>) -> Self {
		Self::new(tag.into(), bytes.into().into())
	}
	
	/// DER-deserializes the data from `source`
	pub fn deserialize<'a>(mut source: impl Iterator<Item = &'a u8>) -> Result<Self, Asn1DerError> {
		let tag = DerTag::deserialize(&mut source)?;
		let len = DerLength::deserialize(&mut source)?;
		let value = DerValue::deserialize(&mut source, len)?;
		Ok(Self{ tag, value })
	}
	
	/// The length of the DER-serialized representation of `self`
	pub fn serialized_len(&self) -> usize {
		Self::compute_serialized_len(self.value.data.len())
	}
	/// DER-serializes `self` into `buf` and returns the amount of bytes written
	pub fn serialize<'a>(&self, mut buf: impl Iterator<Item = &'a mut u8>)
		-> Result<usize, Asn1DerError>
	{
		self.tag.serialize(&mut buf)?;
		DerLength::from(self.value.serialized_len()).serialize(&mut buf)?;
		self.value.serialize(&mut buf)?;
		Ok(self.serialized_len())
	}
	
	/// Efficiently computes the length of the DER-serialized representation of an object with
	/// `payload_len` payload bytes
	pub fn compute_serialized_len(payload_len: usize) -> usize {
		DerTag::compute_serialized_len()
			+ DerLength::compute_serialized_len(payload_len)
			+ DerValue::compute_serialized_len(payload_len)
	}
}