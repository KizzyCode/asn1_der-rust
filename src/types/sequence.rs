use ::{ Asn1DerError, types::{ FromDerObject, IntoDerObject }, der::{ DerObject, DerTag} };

impl<T> FromDerObject for Vec<T> where T: FromDerObject {
	fn from_der_object(der_object: DerObject) -> Result<Self, Asn1DerError> {
		if der_object.tag != DerTag::Sequence { return Err(Asn1DerError::InvalidTag) }
		
		// Parse objects
		let mut slice = der_object.value.data.iter();
		
		let mut objects = Vec::new();
		while slice.len() > 0 {
			objects.push(T::deserialize(&mut slice)?);
		}
		Ok(objects)
	}
}
impl<T> IntoDerObject for Vec<T> where T: IntoDerObject {
	fn into_der_object(self) -> DerObject {
		// Compute the total length and allocate the buffer
		let len: usize = self.iter().map(|o| o.serialized_len()).sum();
		let mut payload_buf = vec![0u8; len];
		
		// Serialize objects
		{
			let mut payload = payload_buf.iter_mut();
			for object in self {
				object.serialize(&mut payload).unwrap();
			}
		}
		DerObject::new(DerTag::Sequence, payload_buf.into())
	}
	
	fn serialized_len(&self) -> usize {
		let len = self.iter().map(|o| o.serialized_len()).sum();
		DerObject::compute_serialized_len(len)
	}
}