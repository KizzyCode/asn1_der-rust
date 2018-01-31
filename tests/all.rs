#[cfg(test)]
mod tests {
	extern crate asn1_der;
	use self::asn1_der::FromDer;
	
	fn hex_to_vec(hex: &str) -> Vec<u8> {
		// Prepare and validate hex-string
		let clean_hex_string = hex.replace(" ", "").to_lowercase();
		if clean_hex_string.len() % 2 != 0 { panic!("Hex-string must contain an even number of chars") }
		
		// Decode hex-string
		let hex_chars = b"0123456789abcdef";
		let mut decoded = Vec::<u8>::with_capacity(hex.len() / 2);
		
		let mut iter = clean_hex_string.bytes();
		while let (Some(n0), Some(n1)) = (iter.next(), iter.next()) {
			decoded.push((hex_chars.binary_search(&n0).expect("Invalid hex-char") << 4 | hex_chars.binary_search(&n1).expect("Invalid hex-char")) as u8)
		}
		decoded
	}
	
	
	#[test]
	fn generics_ok() {
		let generics: Vec<(&str, (u8, &str))> = vec![
			// Some valid generic-objects
			("05 00", (0x05, "")), // Null-object
			("04 02 37e4", (0x04, "37e4")),
			("04 7F 330e8db91b33215c0e533fd28e34cc8b09a808877dc7d82741930431bd09d0d6f31a687d4060126f0ce0360acf95de812fa42f62f67197e049603b65748fd257e3c1611db454a496a6b3f43b27aa5aebc92358921b275479e67cb17983005b085b852f0c2f8d34472ca470dfb0a39b61336dd391848197686754b2ee57fd84",
			 (0x04, "330e8db91b33215c0e533fd28e34cc8b09a808877dc7d82741930431bd09d0d6f31a687d4060126f0ce0360acf95de812fa42f62f67197e049603b65748fd257e3c1611db454a496a6b3f43b27aa5aebc92358921b275479e67cb17983005b085b852f0c2f8d34472ca470dfb0a39b61336dd391848197686754b2ee57fd84")),
			("04 8180 e74bfaed07201437effc07f1bd1ac37cb999fe4db8267b6a6f03dd08af0fb84ca279d2e596decdad1f4d41cf4a3a0343a68dca20ec073c8d0016a073145f2ff96e137d9a4ae681d0d98f267c1dd17d47db49c30d03c33dc906f31a229cab5c2f3d1c4b732d319e8f4ae0afaa99eeea73484e01947e57d71f2d82ba0ab2430fd3",
			 (0x04, "e74bfaed07201437effc07f1bd1ac37cb999fe4db8267b6a6f03dd08af0fb84ca279d2e596decdad1f4d41cf4a3a0343a68dca20ec073c8d0016a073145f2ff96e137d9a4ae681d0d98f267c1dd17d47db49c30d03c33dc906f31a229cab5c2f3d1c4b732d319e8f4ae0afaa99eeea73484e01947e57d71f2d82ba0ab2430fd3")),
		];
		for (encoded, (tag, payload)) in generics {
			// Test decoding
			let decoded = asn1_der::DerObject::from_encoded(hex_to_vec(encoded)).expect("Failed to decode valid DER-object");
			assert_eq!(decoded.tag, tag);
			assert_eq!(decoded.payload, hex_to_vec(payload));
			// Test encoding
			let reencoded = decoded.into_encoded();
			assert_eq!(reencoded, hex_to_vec(encoded));
		}
	}
	#[test]
	fn generics_err() {
		let generics: Vec<(&str, asn1_der::ErrorType)> = vec![
			// asn1_der::der_length::decode_length
			("04 82ff", asn1_der::ErrorType::LengthMismatch), // Length is too short
			("04 8101 7e", asn1_der::ErrorType::InvalidEncoding), // Complex length-encoding for < 128
			("04", asn1_der::ErrorType::LengthMismatch), // There is no length
			// asn1_der::Generic::from_der_encoded
			("", asn1_der::ErrorType::LengthMismatch), // No data present
			("04 02 ff", asn1_der::ErrorType::LengthMismatch), // Payload is too short
		];
		for (encoded, error) in generics {
			let decoding_err = asn1_der::DerObject::from_encoded(hex_to_vec(encoded)).expect_err("Decoded invalid DER-object without error");
			assert_eq!(decoding_err.error_type, error);
		}
	}
	
	
	#[test]
	fn octet_strings_ok() {
		let octet_strings: Vec<(&str, &str)> = vec![
			("04 02 37e4", "37e4"),
			("04 7F 330e8db91b33215c0e533fd28e34cc8b09a808877dc7d82741930431bd09d0d6f31a687d4060126f0ce0360acf95de812fa42f62f67197e049603b65748fd257e3c1611db454a496a6b3f43b27aa5aebc92358921b275479e67cb17983005b085b852f0c2f8d34472ca470dfb0a39b61336dd391848197686754b2ee57fd84",
			 "330e8db91b33215c0e533fd28e34cc8b09a808877dc7d82741930431bd09d0d6f31a687d4060126f0ce0360acf95de812fa42f62f67197e049603b65748fd257e3c1611db454a496a6b3f43b27aa5aebc92358921b275479e67cb17983005b085b852f0c2f8d34472ca470dfb0a39b61336dd391848197686754b2ee57fd84"),
			("04 8180 e74bfaed07201437effc07f1bd1ac37cb999fe4db8267b6a6f03dd08af0fb84ca279d2e596decdad1f4d41cf4a3a0343a68dca20ec073c8d0016a073145f2ff96e137d9a4ae681d0d98f267c1dd17d47db49c30d03c33dc906f31a229cab5c2f3d1c4b732d319e8f4ae0afaa99eeea73484e01947e57d71f2d82ba0ab2430fd3",
			 "e74bfaed07201437effc07f1bd1ac37cb999fe4db8267b6a6f03dd08af0fb84ca279d2e596decdad1f4d41cf4a3a0343a68dca20ec073c8d0016a073145f2ff96e137d9a4ae681d0d98f267c1dd17d47db49c30d03c33dc906f31a229cab5c2f3d1c4b732d319e8f4ae0afaa99eeea73484e01947e57d71f2d82ba0ab2430fd3"),
		];
		for (encoded, data) in octet_strings {
			// From generic-object
			let decoded = asn1_der::DerObject::from_encoded(hex_to_vec(encoded)).expect("Failed to decode valid DER-object");
			let octet_string = Vec::<u8>::from_der(decoded.clone()).expect("Failed to parse valid octet-string");
			assert_eq!(octet_string, hex_to_vec(data));
			// To generic-object
			assert_eq!(asn1_der::DerObject::from(octet_string), decoded);
		}
	}
	#[test]
	fn octet_strings_err() {
		let octet_strings: Vec<(&str, asn1_der::ErrorType)> = vec![
			("05 02 37e4", asn1_der::ErrorType::InvalidTag)
		];
		for (encoded, error) in octet_strings {
			let decoded = asn1_der::DerObject::from_encoded(hex_to_vec(encoded)).expect("Failed to decode valid DER-object");
			let decoding_err = Vec::<u8>::from_der(decoded).expect_err("Parsed invalid octet-string");
			assert_eq!(decoding_err.error_type, error);
		}
	}
	
	
	#[test]
	fn utf8_strings_ok() {
		let utf8_strings: Vec<(&str, &str)> = vec![
			("0c 19 536f6d65205554462d3820456d6f6a6920f09f9696f09f8fbd", "Some UTF-8 Emoji 🖖🏽")
		];
		for (encoded, string) in utf8_strings {
			// From generic-object
			let decoded = asn1_der::DerObject::from_encoded(hex_to_vec(encoded)).expect("Failed to decode valid DER-object");
			let utf8_string = String::from_der(decoded.clone()).expect("Failed to parse valid UTF-8-string");
			assert_eq!(utf8_string, string);
			// To generic-object
			assert_eq!(asn1_der::DerObject::from(utf8_string), decoded);
		}
	}
	#[test]
	fn utf8_strings_err() {
		let utf8_strings: Vec<(&str, asn1_der::ErrorType)> = vec![
			("0d 19 536f6d65205554462d3820456d6f6a6920f09f9696f09f8fbd", asn1_der::ErrorType::InvalidTag),
			("0c 04 f0288c28", asn1_der::ErrorType::InvalidEncoding)
		];
		for (encoded, error) in utf8_strings {
			let decoded = asn1_der::DerObject::from_encoded(hex_to_vec(encoded)).expect("Failed to decode valid DER-object");
			let decoding_err = String::from_der(decoded).expect_err("Parsed invalid UTF-8-string");
			assert_eq!(decoding_err.error_type, error);
		}
	}
	
	
	#[test]
	fn integers_ok() {
		let integers: Vec<(&str, u64)> = vec![
			("02 01 07", 7u64),
			("02 08 7ff7d317cef1a726", 9221070861274031910u64),
			("02 09 0080a54c7fe50d84a0", 9269899520199460000u64),
			("02 09 00ffffffffffffffff", 18446744073709551615u64)
		];
		for (encoded, value) in integers {
			// From generic-object
			let decoded = asn1_der::DerObject::from_encoded(hex_to_vec(encoded)).expect("Failed to decode valid DER-object");
			let integer = u64::from_der(decoded.clone()).expect("Failed to parse valid integer");
			assert_eq!(integer, value);
			// To generic-object
			assert_eq!(asn1_der::DerObject::from(integer), decoded);
		}
	}
	#[test]
	fn integers_err() {
		let integers: Vec<(&str, asn1_der::ErrorType)> = vec![
			("03 01 07", asn1_der::ErrorType::InvalidTag),
			("02 00", asn1_der::ErrorType::InvalidEncoding),
			("02 01 87", asn1_der::ErrorType::Unsupported),
			("02 09 01e3a54c7fe50d84a0", asn1_der::ErrorType::Unsupported)
		];
		for (encoded, error) in integers {
			let decoded = asn1_der::DerObject::from_encoded(hex_to_vec(encoded)).expect("Failed to decode valid DER-object");
			let decoding_err = u64::from_der(decoded).expect_err("Parsed invalid integer");
			assert_eq!(decoding_err.error_type, error);
		}
	}
	
	
	#[test]
	fn sequences_ok() {
		let sequences: Vec<(&str, Vec<&str>)> = vec![
			("30 00", vec![]),
			("30 04  04 02 37e4", vec!["04 02 37e4"]),
			("30 81 87  04 02 37e4  04 8180 72330e8db91b33215c0e533fd28e34cc8b09a808877dc7d82741930431bd09d0d6f31a687d4060126f0ce0360acf95de812fa42f62f67197e049603b65748fd257e3c1611db454a496a6b3f43b27aa5aebc92358921b275479e67cb17983005b085b852f0c2f8d34472ca470dfb0a39b61336dd391848197686754b2ee57fd84",
			 vec!["04 02 37e4", "04 8180 72330e8db91b33215c0e533fd28e34cc8b09a808877dc7d82741930431bd09d0d6f31a687d4060126f0ce0360acf95de812fa42f62f67197e049603b65748fd257e3c1611db454a496a6b3f43b27aa5aebc92358921b275479e67cb17983005b085b852f0c2f8d34472ca470dfb0a39b61336dd391848197686754b2ee57fd84"])
		];
		for (encoded, sequence_elements) in sequences {
			// From generic-object
			let decoded = asn1_der::DerObject::from_encoded(hex_to_vec(encoded)).expect("Failed to decode valid DER-object");
			let sequence = Vec::<asn1_der::DerObject>::from_der(decoded.clone()).expect("Failed to parse valid sequence");
			// Parse reference-elements
			let reference_elements = sequence_elements.iter().map(|x| asn1_der::DerObject::from_encoded(hex_to_vec(x)).expect("Failed to parse reference-element")).collect::<Vec<asn1_der::DerObject>>();
			assert_eq!(sequence, reference_elements);
			// To generic-object
			assert_eq!(asn1_der::DerObject::from(sequence), decoded);
		}
	}
	#[test]
	fn sequences_err() {
		let sequences: Vec<(&str, asn1_der::ErrorType)> = vec![
			("31 00", asn1_der::ErrorType::InvalidTag),
			("30 04  05 03 37e4", asn1_der::ErrorType::LengthMismatch)
		];
		for (encoded, error) in sequences {
			let decoded = asn1_der::DerObject::from_encoded(hex_to_vec(encoded)).expect("Failed to decode valid DER-object");
			let decoding_err = Vec::<asn1_der::DerObject>::from_der(decoded).expect_err("Parsed invalid sequence");
			assert_eq!(decoding_err.error_type, error);
		}
	}
}
