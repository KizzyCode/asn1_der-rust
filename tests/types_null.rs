extern crate asn1_der;
use ::asn1_der::{ Asn1DerError, IntoDerObject, FromDerObject };


#[test]
fn test_ok() {
	fn test(bytes: &&[u8]) {
		// Test deserialization
		let deserialized: () = <()>::deserialize(bytes.iter()).unwrap();
		
		// Test length prediction
		assert_eq!(deserialized.serialized_len(), bytes.len());
		
		// Test serialization
		let mut target = [0u8; 2];
		deserialized.serialize(target.iter_mut()).unwrap();
		assert_eq!(*bytes, &target);
	}
	
	[
		b"\x05\x00".as_ref()
	].iter().for_each(test);
}


#[test]
fn test_err() {
	fn test((bytes, error): &(&[u8], Asn1DerError)) {
		assert_eq!(<()>::deserialize(bytes.iter()).unwrap_err(), *error);
	}
	
	[
		// Invalid tag
		(b"\x06\x00".as_ref(), Asn1DerError::InvalidTag),
		// Invalid encoding
		(b"\x05\x01\x00".as_ref(), Asn1DerError::InvalidEncoding),
		// Length mismatch
		(b"\x05\x02\x00", Asn1DerError::LengthMismatch)
	].iter().for_each(test);
}