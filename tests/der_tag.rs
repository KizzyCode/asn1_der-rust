extern crate asn1_der;
use ::{
	std::{ collections::HashMap, u8 },
	asn1_der::{ Asn1DerError, DerTag }
};

macro_rules! tags {
	(map: $($key:expr => $value:expr),+) => ({
		let mut dict = HashMap::new();
		$(dict.insert($key, $value);)+
		dict
	});
	() => (tags!(map:
		0x01 => DerTag::Boolean,
		0x02 => DerTag::Integer,
		0x04 => DerTag::OctetString,
		0x05 => DerTag::Null,
		0x0c => DerTag::Utf8String,
		0x30 => DerTag::Sequence,

		0x00 => DerTag::x00, /* Boolean        */ /* Integer        */ 0x03 => DerTag::x03,
		/* OctetString    */ /* Null           */ 0x06 => DerTag::x06, 0x07 => DerTag::x07,
		0x08 => DerTag::x08, 0x09 => DerTag::x09, 0x0a => DerTag::x0a, 0x0b => DerTag::x0b,
		/* Utf8String     */ 0x0d => DerTag::x0d, 0x0e => DerTag::x0e, 0x0f => DerTag::x0f,
		0x10 => DerTag::x10, 0x11 => DerTag::x11, 0x12 => DerTag::x12, 0x13 => DerTag::x13,
		0x14 => DerTag::x14, 0x15 => DerTag::x15, 0x16 => DerTag::x16, 0x17 => DerTag::x17,
		0x18 => DerTag::x18, 0x19 => DerTag::x19, 0x1a => DerTag::x1a, 0x1b => DerTag::x1b,
		0x1c => DerTag::x1c, 0x1d => DerTag::x1d, 0x1e => DerTag::x1e, 0x1f => DerTag::x1f,
		0x20 => DerTag::x20, 0x21 => DerTag::x21, 0x22 => DerTag::x22, 0x23 => DerTag::x23,
		0x24 => DerTag::x24, 0x25 => DerTag::x25, 0x26 => DerTag::x26, 0x27 => DerTag::x27,
		0x28 => DerTag::x28, 0x29 => DerTag::x29, 0x2a => DerTag::x2a, 0x2b => DerTag::x2b,
		0x2c => DerTag::x2c, 0x2d => DerTag::x2d, 0x2e => DerTag::x2e, 0x2f => DerTag::x2f,
		/* Sequence       */ 0x31 => DerTag::x31, 0x32 => DerTag::x32, 0x33 => DerTag::x33,
		0x34 => DerTag::x34, 0x35 => DerTag::x35, 0x36 => DerTag::x36, 0x37 => DerTag::x37,
		0x38 => DerTag::x38, 0x39 => DerTag::x39, 0x3a => DerTag::x3a, 0x3b => DerTag::x3b,
		0x3c => DerTag::x3c, 0x3d => DerTag::x3d, 0x3e => DerTag::x3e, 0x3f => DerTag::x3f,
		0x40 => DerTag::x40, 0x41 => DerTag::x41, 0x42 => DerTag::x42, 0x43 => DerTag::x43,
		0x44 => DerTag::x44, 0x45 => DerTag::x45, 0x46 => DerTag::x46, 0x47 => DerTag::x47,
		0x48 => DerTag::x48, 0x49 => DerTag::x49, 0x4a => DerTag::x4a, 0x4b => DerTag::x4b,
		0x4c => DerTag::x4c, 0x4d => DerTag::x4d, 0x4e => DerTag::x4e, 0x4f => DerTag::x4f,
		0x50 => DerTag::x50, 0x51 => DerTag::x51, 0x52 => DerTag::x52, 0x53 => DerTag::x53,
		0x54 => DerTag::x54, 0x55 => DerTag::x55, 0x56 => DerTag::x56, 0x57 => DerTag::x57,
		0x58 => DerTag::x58, 0x59 => DerTag::x59, 0x5a => DerTag::x5a, 0x5b => DerTag::x5b,
		0x5c => DerTag::x5c, 0x5d => DerTag::x5d, 0x5e => DerTag::x5e, 0x5f => DerTag::x5f,
		0x60 => DerTag::x60, 0x61 => DerTag::x61, 0x62 => DerTag::x62, 0x63 => DerTag::x63,
		0x64 => DerTag::x64, 0x65 => DerTag::x65, 0x66 => DerTag::x66, 0x67 => DerTag::x67,
		0x68 => DerTag::x68, 0x69 => DerTag::x69, 0x6a => DerTag::x6a, 0x6b => DerTag::x6b,
		0x6c => DerTag::x6c, 0x6d => DerTag::x6d, 0x6e => DerTag::x6e, 0x6f => DerTag::x6f,
		0x70 => DerTag::x70, 0x71 => DerTag::x71, 0x72 => DerTag::x72, 0x73 => DerTag::x73,
		0x74 => DerTag::x74, 0x75 => DerTag::x75, 0x76 => DerTag::x76, 0x77 => DerTag::x77,
		0x78 => DerTag::x78, 0x79 => DerTag::x79, 0x7a => DerTag::x7a, 0x7b => DerTag::x7b,
		0x7c => DerTag::x7c, 0x7d => DerTag::x7d, 0x7e => DerTag::x7e, 0x7f => DerTag::x7f,
		0x80 => DerTag::x80, 0x81 => DerTag::x81, 0x82 => DerTag::x82, 0x83 => DerTag::x83,
		0x84 => DerTag::x84, 0x85 => DerTag::x85, 0x86 => DerTag::x86, 0x87 => DerTag::x87,
		0x88 => DerTag::x88, 0x89 => DerTag::x89, 0x8a => DerTag::x8a, 0x8b => DerTag::x8b,
		0x8c => DerTag::x8c, 0x8d => DerTag::x8d, 0x8e => DerTag::x8e, 0x8f => DerTag::x8f,
		0x90 => DerTag::x90, 0x91 => DerTag::x91, 0x92 => DerTag::x92, 0x93 => DerTag::x93,
		0x94 => DerTag::x94, 0x95 => DerTag::x95, 0x96 => DerTag::x96, 0x97 => DerTag::x97,
		0x98 => DerTag::x98, 0x99 => DerTag::x99, 0x9a => DerTag::x9a, 0x9b => DerTag::x9b,
		0x9c => DerTag::x9c, 0x9d => DerTag::x9d, 0x9e => DerTag::x9e, 0x9f => DerTag::x9f,
		0xa0 => DerTag::xa0, 0xa1 => DerTag::xa1, 0xa2 => DerTag::xa2, 0xa3 => DerTag::xa3,
		0xa4 => DerTag::xa4, 0xa5 => DerTag::xa5, 0xa6 => DerTag::xa6, 0xa7 => DerTag::xa7,
		0xa8 => DerTag::xa8, 0xa9 => DerTag::xa9, 0xaa => DerTag::xaa, 0xab => DerTag::xab,
		0xac => DerTag::xac, 0xad => DerTag::xad, 0xae => DerTag::xae, 0xaf => DerTag::xaf,
		0xb0 => DerTag::xb0, 0xb1 => DerTag::xb1, 0xb2 => DerTag::xb2, 0xb3 => DerTag::xb3,
		0xb4 => DerTag::xb4, 0xb5 => DerTag::xb5, 0xb6 => DerTag::xb6, 0xb7 => DerTag::xb7,
		0xb8 => DerTag::xb8, 0xb9 => DerTag::xb9, 0xba => DerTag::xba, 0xbb => DerTag::xbb,
		0xbc => DerTag::xbc, 0xbd => DerTag::xbd, 0xbe => DerTag::xbe, 0xbf => DerTag::xbf,
		0xc0 => DerTag::xc0, 0xc1 => DerTag::xc1, 0xc2 => DerTag::xc2, 0xc3 => DerTag::xc3,
		0xc4 => DerTag::xc4, 0xc5 => DerTag::xc5, 0xc6 => DerTag::xc6, 0xc7 => DerTag::xc7,
		0xc8 => DerTag::xc8, 0xc9 => DerTag::xc9, 0xca => DerTag::xca, 0xcb => DerTag::xcb,
		0xcc => DerTag::xcc, 0xcd => DerTag::xcd, 0xce => DerTag::xce, 0xcf => DerTag::xcf,
		0xd0 => DerTag::xd0, 0xd1 => DerTag::xd1, 0xd2 => DerTag::xd2, 0xd3 => DerTag::xd3,
		0xd4 => DerTag::xd4, 0xd5 => DerTag::xd5, 0xd6 => DerTag::xd6, 0xd7 => DerTag::xd7,
		0xd8 => DerTag::xd8, 0xd9 => DerTag::xd9, 0xda => DerTag::xda, 0xdb => DerTag::xdb,
		0xdc => DerTag::xdc, 0xdd => DerTag::xdd, 0xde => DerTag::xde, 0xdf => DerTag::xdf,
		0xe0 => DerTag::xe0, 0xe1 => DerTag::xe1, 0xe2 => DerTag::xe2, 0xe3 => DerTag::xe3,
		0xe4 => DerTag::xe4, 0xe5 => DerTag::xe5, 0xe6 => DerTag::xe6, 0xe7 => DerTag::xe7,
		0xe8 => DerTag::xe8, 0xe9 => DerTag::xe9, 0xea => DerTag::xea, 0xeb => DerTag::xeb,
		0xec => DerTag::xec, 0xed => DerTag::xed, 0xee => DerTag::xee, 0xef => DerTag::xef,
		0xf0 => DerTag::xf0, 0xf1 => DerTag::xf1, 0xf2 => DerTag::xf2, 0xf3 => DerTag::xf3,
		0xf4 => DerTag::xf4, 0xf5 => DerTag::xf5, 0xf6 => DerTag::xf6, 0xf7 => DerTag::xf7,
		0xf8 => DerTag::xf8, 0xf9 => DerTag::xf9, 0xfa => DerTag::xfa, 0xfb => DerTag::xfb,
		0xfc => DerTag::xfc, 0xfd => DerTag::xfd, 0xfe => DerTag::xfe, 0xff => DerTag::xff
	))
}


#[test]
fn test_ok() {
	let map: HashMap<u8, DerTag> = tags!();
	
	// Assert that we really have 256 keys so that we have a 1:1 relationship between `Tag` and `u8`
	assert_eq!(map.len(), (u8::MIN..=u8::MAX).count());
	
	// Match each possible key-value combination
	for (value, tag) in map.iter() {
		assert_eq!(DerTag::from(*value), *tag);
		assert_eq!(*value, u8::from(*tag));
	}
	
	// Test coding
	let mut buf_slice = [0u8];
	for (value, tag) in map.iter() {
		buf_slice[0] = *value;
		
		// Test deserialization
		let deserialized = DerTag::deserialize(buf_slice.iter()).unwrap();
		assert_eq!(deserialized, *tag);
		
		// Test length prediction
		assert_eq!(tag.serialized_len(), 1);
		
		// Test serialization
		deserialized.serialize(buf_slice.iter_mut()).unwrap();
		assert_eq!(*value, buf_slice[0]);
	}
}


#[test]
fn test_err() {
	let empty_slice: [u8; 0] = [];
	assert_eq!(
		DerTag::deserialize(empty_slice.iter()).unwrap_err(),
		Asn1DerError::LengthMismatch
	)
}