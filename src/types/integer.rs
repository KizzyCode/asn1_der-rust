use ::{ Asn1DerError, types::{ FromDerObject, IntoDerObject }, der::{ DerObject, DerTag } };


macro_rules! impl_conv {
	(decl: $uint:ident) => (
		/// Converts `self` or returns `Asn1DerError::Unsupported` if `self` is too large
		fn $uint(self) -> Result<$uint, Asn1DerError>;
	);
	(impl: $uint:ident) => (
		fn $uint(self) -> Result<$uint, Asn1DerError> {
			if self > $uint::max_value() as u128 { Err(Asn1DerError::Unsupported) }
				else { Ok(self as $uint) }
		}
	);
}


/// An extension that allows you to safely convert a `u128` to a smaller type
pub trait U128Ext {
	impl_conv!(decl: usize);
	impl_conv!(decl: u64);
	impl_conv!(decl: u32);
	impl_conv!(decl: u16);
	impl_conv!(decl: u8);
}
impl U128Ext for u128 {
	impl_conv!(impl: usize);
	impl_conv!(impl: u64);
	impl_conv!(impl: u32);
	impl_conv!(impl: u16);
	impl_conv!(impl: u8);
}


impl FromDerObject for u128 {
	fn from_der_object(der_object: DerObject) -> Result<Self, Asn1DerError> {
		// Validate the tag and check that we have at least one byte
		if der_object.tag != DerTag::Integer { return Err(Asn1DerError::InvalidTag) }
		if der_object.value.data.is_empty() { return Err(Asn1DerError::InvalidEncoding) }
		
		// Initialize vars
		let mut data = der_object.value.data.iter().peekable();
		
		// Check the first byte
		let unsigned = match **data.peek().ok_or(Asn1DerError::InvalidEncoding)? {
			// The number is signed
			b if b > 0x7f => return Err(Asn1DerError::Unsupported),
			// Check if the number has a leading zero byte
			0x00 => {
				data.next().unwrap();
				true
			},
			_ => false
		};
		
		// Validate the second byte
		if unsigned { match data.peek().and_then(|b| Some(**b)) {
			// A number must only have one leading zero byte
			Some(b) if b < 0x80 => return Err(Asn1DerError::InvalidEncoding),
			// The number has a leading zero even if it's value does not start with a `1`-bit
			Some(0x00) => return Err(Asn1DerError::InvalidEncoding),
			_ => ()
		} }
		
		// Check if the number fits in a `u128`
		if data.len() > 16 { return Err(Asn1DerError::Unsupported) }
		
		// Decode the number
		let (mut value, mut shl) = (0u128, data.len() as u128);
		while let Some(b) = data.next() {
			shl -= 1;
			value += (*b as u128) << (shl * 8);
		}
		Ok(value)
	}
}
impl IntoDerObject for u128 {
	fn into_der_object(self) -> DerObject {
		// Compute the payload length
		let num_len = 16 - (self.leading_zeros() as usize / 8);
		// Is true if either the first bit i `1` or if the number is `0`
		let push_leading_zero = self.leading_zeros() % 8 == 0;
		
		// Encode number and prepend leading zero if necessary
		let mut payload = Vec::new();
		for i in (0..num_len).rev() {
			payload.push((self >> (i * 8)) as u8);
		}
		
		// Check if the first byte starts with an `1` bit
		if push_leading_zero { payload.insert(0, 0x00) }
		
		DerObject::new(DerTag::Integer, payload.into())
	}
	
	fn serialized_len(&self) -> usize {
		let mut num_len = 16 - (self.leading_zeros() as usize / 8);
		// Is true if either the first bit i `1` or if the number is `0`
		if self.leading_zeros() % 8 == 0 { num_len += 1 }
		
		DerObject::compute_serialized_len(num_len)
	}
}