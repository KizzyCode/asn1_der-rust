extern crate asn1_der;
use ::asn1_der::{ Asn1DerError, DerLength };


#[test]
fn test_ok() {
	fn test((bytes, length): &(&[u8], usize)) {
		// Test deserialization
		let deserialized = DerLength::deserialize(bytes.iter()).unwrap();
		assert_eq!(*length, deserialized.into());
		
		// Test length prediction
		assert_eq!(deserialized.serialized_len(), bytes.len());
		
		// Test serialization
		let mut target = [0u8; 9];
		deserialized.serialize(target.iter_mut()).unwrap();
		assert_eq!(*bytes, &target[..bytes.len()]);
	}
	
	// Test 32 bit lengths [0, 2^32)
	[
		// Test simple lengths
		(b"\x00".as_ref(), 0),
		(b"\x47".as_ref(), 71),
		(b"\x7f".as_ref(), 127),
		
		// Test complex lengths [128, 2^16)
		(b"\x81\x80".as_ref(), 128),
		(b"\x81\xf7".as_ref(), 247),
		(b"\x82\xf7\xf7".as_ref(), 63_479),
		(b"\x82\xff\xff".as_ref(), 65_535),
		
		// Test complex lengths [2^16, 2^32)
		(b"\x83\x01\x00\x00".as_ref(), 65_536),
		(b"\x83\xf7\x7f\x44".as_ref(), 16_219_972),
		(b"\x84\xf7\x7f\x44\x01".as_ref(), 4_152_312_833),
		(b"\x84\xff\xff\xff\xff".as_ref(), 4_294_967_295)
	].iter().for_each(test);
	
	// Test 64 bit lengths [2^32, 2^64)
	#[cfg(target_pointer_width = "64")]
	[
		(b"\x85\x01\x00\x00\x00\x00".as_ref(), 4_294_967_296),
		(b"\x85\xf7\x7f\x44\x01\xb7".as_ref(), 1_062_992_085_431),
		(b"\x86\xf7\x7f\x44\x01\xb7\xc5".as_ref(), 272_125_973_870_533),
		(b"\x87\xf7\x7f\x44\x01\xb7\xc5\x23".as_ref(), 69_664_249_310_856_483),
		(b"\x88\xf7\x7f\x44\x01\xb7\xc5\x23\x00".as_ref(), 17_834_047_823_579_259_648),
		(b"\x88\xff\xff\xff\xff\xff\xff\xff\xff".as_ref(), 18_446_744_073_709_551_615)
	].iter().for_each(test);
}


#[test]
fn test_err() {
	fn test((bytes, error): &(&[u8], Asn1DerError)) {
		assert_eq!(DerLength::deserialize(bytes.iter()).unwrap_err(), *error);
	}
	
	[
		// Invalid complex length
		(b"\x80".as_ref(), Asn1DerError::InvalidEncoding),
		// Invalid use of a complex length
		(b"\x81\x7f".as_ref(), Asn1DerError::InvalidEncoding),
		// Incomplete length
		(b"\x81".as_ref(), Asn1DerError::LengthMismatch),
		// Incomplete length
		(b"\x84\x01\x00\x00".as_ref(), Asn1DerError::LengthMismatch),
		// Complex length > 2^64 - 1
		(b"\x89\x01\x00\x00\x00\x00\x00\x00\x00\x00".as_ref(), Asn1DerError::Unsupported)
	].iter().for_each(test);
}