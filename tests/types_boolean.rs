extern crate asn1_der;
use ::asn1_der::{ Asn1DerError, IntoDerObject, FromDerObject };


#[test]
fn test_ok() {
	fn test((bytes, boolean): &(&[u8], bool)) {
		// Test deserialization
		let deserialized = bool::deserialize(bytes.iter()).unwrap();
		assert_eq!(*boolean, deserialized.into());
		
		// Test length prediction
		assert_eq!(deserialized.serialized_len(), bytes.len());
		
		// Test serialization
		let mut target = [0u8; 3];
		deserialized.serialize(target.iter_mut()).unwrap();
		assert_eq!(*bytes, &target);
	}
	
	[
		(b"\x01\x01\x00".as_ref(), false),
		(b"\x01\x01\xff".as_ref(), true)
	].iter().for_each(test);
}


#[test]
fn test_err() {
	fn test((bytes, error): &(&[u8], Asn1DerError)) {
		assert_eq!(bool::deserialize(bytes.iter()).unwrap_err(), *error);
	}
	
	[
		// Invalid tag
		(b"\x02\x01\x00".as_ref(), Asn1DerError::InvalidTag),
		// Invalid value
		(b"\x01\x01\x01".as_ref(), Asn1DerError::InvalidEncoding),
		// One byte too much
		(b"\x01\x02\x00\x00".as_ref(), Asn1DerError::InvalidEncoding),
		// Length mismatch
		(b"\x01\x02\x00".as_ref(), Asn1DerError::LengthMismatch)
	].iter().for_each(test);
}