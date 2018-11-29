extern crate asn1_der;
use ::asn1_der::{ Asn1DerError, IntoDerObject, FromDerObject };


#[test]
fn test_ok() {
	fn test((bytes, boolean): &(&[u8], u128)) {
		// Test deserialization
		let deserialized = u128::deserialize(bytes.iter()).unwrap();
		assert_eq!(*boolean, deserialized.into());
		
		// Test length prediction
		assert_eq!(deserialized.serialized_len(), bytes.len());
		
		// Test serialization
		let mut target = [0u8; 19];
		deserialized.serialize(target.iter_mut()).unwrap();
		assert_eq!(*bytes, &target[..bytes.len()]);
	}
	
	[
		(b"\x02\x01\x00".as_ref(), 0),
		(b"\x02\x01\x07".as_ref(), 7),
		(b"\x02\x02\x00\x80".as_ref(), 128),
		(b"\x02\x02\x00\xff".as_ref(), 255),
		
		(b"\x02\x02\x7f\xf7".as_ref(), 32759),
		(b"\x02\x03\x00\x80\xa5".as_ref(), 32933),
		(b"\x02\x03\x00\xff\xff".as_ref(), 65535),
		
		(b"\x02\x04\x7f\xf7\xd3\x17".as_ref(), 2146947863),
		(b"\x02\x05\x00\x80\xa5\x4c\x7f".as_ref(), 2158316671),
		(b"\x02\x05\x00\xff\xff\xff\xff".as_ref(), 4294967295),
		
		(b"\x02\x08\x7f\xf7\xd3\x17\xce\xf1\xa7\x26".as_ref(), 9221070861274031910),
		(b"\x02\x09\x00\x80\xa5\x4c\x7f\xe5\x0d\x84\xa0".as_ref(), 9269899520199460000),
		(b"\x02\x09\x00\xff\xff\xff\xff\xff\xff\xff\xff".as_ref(), 18446744073709551615),
		
		(b"\x02\x10\x7f\xc8\xa3\xa5\x32\x49\xcc\xf2\x73\xb3\xe9\x4d\xe1\xb6\x33\x61".as_ref(), 169853733957366961371495358725388383073),
		(b"\x02\x11\x00\x80\xc8\xa3\xa5\x32\x49\xcc\xf2\x73\xb3\xe9\x4d\xe1\xb6\x33\x61".as_ref(), 171182961953151877244399165785668727649),
		(b"\x02\x11\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff".as_ref(), 340282366920938463463374607431768211455)
	].iter().for_each(test);
}


#[test]
fn test_err() {
	fn test((bytes, error): &(&[u8], Asn1DerError)) {
		assert_eq!(u128::deserialize(bytes.iter()).unwrap_err(), *error);
	}
	
	[
		// Invalid tag
		(b"\x03\x01\x07".as_ref(), Asn1DerError::InvalidTag),
		// Empty payload
		(b"\x02\x00".as_ref(), Asn1DerError::InvalidEncoding),
		// Unsigned number
		(b"\x02\x01\x80".as_ref(), Asn1DerError::Unsupported),
		// Two leading zeros
		(b"\x02\x02\x00\x00", Asn1DerError::InvalidEncoding),
		// Number is too large
		(b"\x02\x11\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".as_ref(), Asn1DerError::Unsupported),
		// Length mismatch
		(b"\x02\x02\x80".as_ref(), Asn1DerError::LengthMismatch),
	].iter().for_each(test);
}