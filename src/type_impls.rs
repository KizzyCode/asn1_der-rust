use super::{ Result, Asn1DerError, DerObject, FromDerObject, IntoDerObject, FromDerEncoded, IntoDerEncoded };

macro_rules! impl_from_der_encoded {
    ($t:ty) => {
    	impl $crate::FromDerEncoded for $t {
			fn from_der_encoded(data: Vec<u8>) -> $crate::Result<Self> {
				let der_object: $crate::DerObject = try_err!($crate::DerObject::from_der_encoded(data));
				Ok(try_err!(Self::from_der_object(der_object)))
			}
			fn with_der_encoded(data: &[u8]) -> $crate::Result<Self> {
				let der_object: $crate::DerObject = try_err!($crate::DerObject::with_der_encoded(data));
				Ok(try_err!(Self::from_der_object(der_object)))
			}
		}
    };
}
macro_rules! impl_into_der_encoded {
    ($t:ty) => {
    	impl $crate::IntoDerEncoded for $t {
			fn into_der_encoded(self) -> Vec<u8> {
				self.into_der_object().into_der_encoded()
			}
		}
    };
}


impl FromDerObject for () {
	fn from_der_object(der_object: DerObject) -> Result<Self> {
		// Validate tag and extract payload
		if der_object.tag != 0x05 { throw_err!(Asn1DerError::InvalidTag) }
		if der_object.payload.len() != 0 { throw_err!(Asn1DerError::InvalidEncoding) }
		Ok(())
	}
}
impl_from_der_encoded!(());

impl FromDerObject for bool {
	fn from_der_object(der_object: DerObject) -> Result<Self> {
		// Validate tag and parse payload
		if der_object.tag != 0x01 { throw_err!(Asn1DerError::InvalidTag) }
		if der_object.payload.len() != 1 || ![0xff, 0x00].contains(&der_object.payload[0]) { throw_err!(Asn1DerError::InvalidEncoding) }
		Ok(der_object.payload[0] == 0xff)
	}
}
impl_from_der_encoded!(bool);

impl FromDerObject for String {
	fn from_der_object(der_object: DerObject) -> Result<Self> {
		// Validate tag and extract payload
		if der_object.tag != 0x0c { throw_err!(Asn1DerError::InvalidTag) }
		if let Ok(string) = String::from_utf8(der_object.payload) { Ok(string) }
			else { throw_err!(Asn1DerError::InvalidEncoding) }
	}
}
impl_from_der_encoded!(String);

macro_rules! impl_from_der_object_num {
	($utype:ty) => {
		impl $crate::FromDerObject for $utype {
			fn from_der_object(der_object: $crate::DerObject) -> $crate::Result<Self> {
				// Validate tag and encoding
				if der_object.tag != 0x02 { throw_err!($crate::Asn1DerError::InvalidTag) }
					else if der_object.payload.len() == 0 { throw_err!($crate::Asn1DerError::InvalidEncoding) }
				
				// The leading byte only indicates that the number is unsigned and can be skipped
				let to_skip = if der_object.payload[0] == 0x00 { 1 } else { 0 };
				
				// Check that the number is not too large or signed and decode it
				if der_object.payload.len() - to_skip > ::std::mem::size_of::<$utype>()
					|| der_object.payload[0] & 0x80 != 0 { throw_err!($crate::Asn1DerError::Unsupported, "Integer is greater than type::MAX") }
				Ok(be_decode!(&der_object.payload[to_skip ..] => $utype))
			}
		}
		impl_from_der_encoded!($utype);
	};
}
impl_from_der_object_num!(usize);
impl_from_der_object_num!(u64);
impl_from_der_object_num!(u32);
impl_from_der_object_num!(u16);

impl FromDerObject for Vec<u8> {
	fn from_der_object(der_object: DerObject) -> Result<Self> {
		// Validate tag and extract payload
		if der_object.tag != 0x04 { throw_err!(Asn1DerError::InvalidTag) }
		Ok(der_object.payload)
	}
}
impl_from_der_encoded!(Vec<u8>);

impl<T> FromDerObject for Vec<T> where T: FromDerObject {
	fn from_der_object(der_object: DerObject) -> Result<Self> {
		// Validate tag
		if der_object.tag != 0x30 { throw_err!(Asn1DerError::InvalidTag) }
		
		// Parse payload
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
impl<T> FromDerEncoded for Vec<T> where T: FromDerObject {
	fn from_der_encoded(data: Vec<u8>) -> Result<Self> {
		let der_object: DerObject = try_err!(DerObject::from_der_encoded(data));
		Ok(try_err!(Self::from_der_object(der_object)))
	}
	fn with_der_encoded(data: &[u8]) -> Result<Self> {
		let der_object: DerObject = try_err!(DerObject::with_der_encoded(data));
		Ok(try_err!(Self::from_der_object(der_object)))
	}
}


impl IntoDerObject for () {
	fn into_der_object(self) -> DerObject {
		DerObject::new(0x05, Vec::new())
	}
}
impl_into_der_encoded!(());

impl IntoDerObject for bool {
	fn into_der_object(self) -> DerObject {
		DerObject::new(0x01, if self { vec![0xff] } else { vec![0x00] })
	}
}
impl_into_der_encoded!(bool);

impl IntoDerObject for String {
	fn into_der_object(self) -> DerObject {
		DerObject::new(0x0c, self.into())
	}
}
impl_into_der_encoded!(String);

macro_rules! impl_into_der_object_num {
	($utype:ty, sized: $itype:ident) => {
		impl $crate::IntoDerObject for $utype {
			fn into_der_object(mut self) -> $crate::DerObject {
				// Check if we need a leading zero-byte as unsigned-indicator
				let leading_zeros = if self > ::std::$itype::MAX as $utype { 1usize } else { 0usize };
				// Compute the payload-size (must be at least one because even `0x00` is represented in one byte)
				let payload_length = ::std::cmp::max(::std::mem::size_of::<$utype>() - (self.leading_zeros() as usize / 8), 1);
				
				// Create payload and encode number
				let mut payload = vec![0u8; leading_zeros + payload_length];
				be_encode!(self => &mut payload[leading_zeros ..]);
				$crate::DerObject::new(0x02, payload)
			}
		}
		impl_into_der_encoded!($utype);
	};
}
impl_into_der_object_num!(usize, sized: isize);
impl_into_der_object_num!(u64, sized: i64);
impl_into_der_object_num!(u32, sized: i32);
impl_into_der_object_num!(u16, sized: i16);

impl IntoDerObject for Vec<u8> {
	fn into_der_object(self) -> DerObject {
		DerObject::new(0x04, self)
	}
}
impl_into_der_encoded!(Vec<u8>);

impl<T> IntoDerObject for Vec<T> where T: IntoDerObject {
	fn into_der_object(self) -> DerObject {
		let mut payload = Vec::new();
		for object in self { payload.append(&mut object.into_der_object().into_der_encoded()) }
		DerObject::new(0x30, payload)
	}
}
impl<T> IntoDerEncoded for Vec<T> where T: IntoDerObject {
	fn into_der_encoded(self) -> Vec<u8> {
		self.into_der_object().into_der_encoded()
	}
}