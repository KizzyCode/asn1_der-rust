use ::{ Asn1DerError, std::mem };


/// The maximum amount of length bytes supported by this platform
const USIZE_LEN: usize = mem::size_of::<usize>();


/// A wrapper around a DER length
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct DerLength {
	/// The length
	pub len: usize
}
impl DerLength {
	/// DER-deserializes a length from `source`
	pub fn deserialize<'a>(mut source: impl Iterator<Item = &'a u8>) -> Result<Self, Asn1DerError> {
		match *source.next().ok_or(Asn1DerError::LengthMismatch)? as usize {
			// Decode simple length
			b @ 0..=127 => Ok(Self{ len: b }),
			
			// Decode complex length
			b => match b & 0x0f {
				b if b > USIZE_LEN => Err(Asn1DerError::Unsupported),
				b => {
					// Decode `b` length bytes
					let mut len = 0;
					for i in (0..b).rev() {
						let b = *source.next().ok_or(Asn1DerError::LengthMismatch)?;
						len += (b as usize) << (i * 8)
					}
					// Validate that our complex length is > 127
					if len < 128 { Err(Asn1DerError::InvalidEncoding) }
						else { Ok(Self{ len }) }
				}
			}
		}
	}
	
	/// The length of the DER-serialized representation of `self`
	pub fn serialized_len(&self) -> usize {
		match self.len {
			// Simple length
			0..=127 => 1,
			// Complex length
			len => 1 + USIZE_LEN - (len.leading_zeros() / 8) as usize
		}
	}
	/// DER-serializes `self` into `buf` and returns the amount of bytes written
	pub fn serialize<'a>(&self, mut buf: impl Iterator<Item = &'a mut u8>)
		-> Result<usize, Asn1DerError>
	{
		let serialized_len = self.serialized_len();
		match self.len {
			// Encode simple length
			len @ 0..=127 => *buf.next().ok_or(Asn1DerError::LengthMismatch)? = len as u8,
			
			// Encode complex length
			len => {
				*buf.next().ok_or(Asn1DerError::LengthMismatch)?
					= (serialized_len as u8 | 0x80) - 1;
				for i in (0..serialized_len - 1).rev() {
					*buf.next().ok_or(Asn1DerError::LengthMismatch)? = (len >> (i * 8)) as u8
				}
			}
		}
		Ok(serialized_len)
	}
	
	/// Efficiently computes the length of the DER-serialized representation of `len`
	pub fn compute_serialized_len(len: usize) -> usize {
		Self::from(len).serialized_len()
	}
}
impl From<usize> for DerLength {
	fn from(len: usize) -> Self {
		DerLength { len }
	}
}
impl From<DerLength> for usize {
	fn from(len: DerLength) -> Self {
		len.len
	}
}