use ::{ Asn1DerError, types::{ FromDerObject, IntoDerObject }, der::{ DerObject, DerTag} };


impl FromDerObject for bool {
	fn from_der_object(der_object: DerObject) -> Result<Self, Asn1DerError> {
		if der_object.tag != DerTag::Boolean { return Err(Asn1DerError::InvalidTag) }
		
		match der_object.value.data.as_slice() {
			&[0x00u8] => Ok(false),
			&[0xffu8] => Ok(true),
			_ => return Err(Asn1DerError::InvalidEncoding)
		}
	}
}
impl IntoDerObject for bool {
	fn into_der_object(self) -> DerObject {
		DerObject::new(DerTag::Boolean, match self {
			true => vec![0xffu8],
			false => vec![0x00u8]
		}.into())
	}
	
	fn serialized_len(&self) -> usize {
		DerObject::compute_serialized_len(1)
	}
}