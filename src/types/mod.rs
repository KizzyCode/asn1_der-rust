use ::{ Asn1DerError, der::DerObject };

mod boolean;
mod integer;
mod null;
mod octet_string;
mod sequence;
mod utf8_string;

pub use self::integer::U128Ext;


/// A trait for converting a DER object into a native element
pub trait FromDerObject where Self: Sized {
	/// Converts `der_object` into `Self`
	fn from_der_object(der_object: DerObject) -> Result<Self, Asn1DerError>;
	
	/// DER-deserializes the data from `source`
	fn deserialize<'a>(source: impl Iterator<Item = &'a u8>) -> Result<Self, Asn1DerError> {
		Self::from_der_object(DerObject::deserialize(source)?)
	}
}
/// A trait for converting native elements into a DER object
pub trait IntoDerObject where Self: Sized {
	/// Converts `self` into a DER object
	fn into_der_object(self) -> DerObject;
	
	/// Efficiently computes the length of the DER-serialized representation of `self`
	fn serialized_len(&self) -> usize;
	
	/// DER-serializes `self` into `buf` and returns the amount of bytes written
	fn serialize<'a>(self, buf: impl Iterator<Item = &'a mut u8>) -> Result<usize, Asn1DerError> {
		// Use this call to avoid recursion
		DerObject::serialize(&self.into_der_object(), buf)
	}
}


impl FromDerObject for DerObject {
	fn from_der_object(der_object: DerObject) -> Result<Self, Asn1DerError> {
		Ok(der_object)
	}
}
impl IntoDerObject for DerObject {
	fn into_der_object(self) -> DerObject {
		self
	}
	fn serialized_len(&self) -> usize {
		self.serialized_len()
	}
}