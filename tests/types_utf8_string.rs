extern crate asn1_der;
use ::asn1_der::{ Asn1DerError, IntoDerObject, FromDerObject };


#[test]
fn test_ok() {
	fn test((bytes, string): &(&[u8], String)) {
		// Test deserialization
		let deserialized = String::deserialize(bytes.iter()).unwrap();
		assert_eq!(*string, deserialized);
		
		// Test length prediction
		assert_eq!(deserialized.serialized_len(), bytes.len());
		
		// Test serialization
		let mut target = vec![0u8; bytes.len()];
		deserialized.serialize(target.iter_mut()).unwrap();
		assert_eq!(*bytes, target.as_slice());
	}
	
	[
		(b"\x0c\x00".as_ref(), String::new()),
		(b"\x0c\x09\x54\x65\x73\x74\x6F\x6C\x6F\x70\x65".as_ref(), "Testolope".to_string()),
		(b"\x0c\x19\x53\x6f\x6d\x65\x20\x55\x54\x46\x2d\x38\x20\x45\x6d\x6f\x6a\x69\x20\xf0\x9f\x96\x96\xf0\x9f\x8f\xbd".as_ref(), "Some UTF-8 Emoji 🖖🏽".to_string())
	].iter().for_each(test);
}


#[test]
fn test_err() {
	fn test((bytes, error): &(&[u8], Asn1DerError)) {
		assert_eq!(String::deserialize(bytes.iter()).unwrap_err(), *error);
	}
	
	[
		// Invalid tag
		(b"\x0d\x00".as_ref(), Asn1DerError::InvalidTag),
		// Invalid encoding
		(b"\x0c\x04\xf0\x28\x8c\x28".as_ref(), Asn1DerError::InvalidEncoding),
		// Length mismatch
		(b"\x0c\x02\x54".as_ref(), Asn1DerError::LengthMismatch),
	].iter().for_each(test);
}