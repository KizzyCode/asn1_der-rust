#![cfg_attr(test, deny(warnings))]

pub mod helpers;

use crate::helpers::{ ResultExt, test_err };
use asn1_der::{ DerObject, der };


#[test]
fn length() {
	for (i, test) in test_err::load().length.into_iter().enumerate() {
		der::length::decode(&mut test.bytes.iter()).assert_err(&test.err, i);
	}
}


#[test]
fn object() {
	for (i, test) in test_err::load().object.into_iter().enumerate() {
		DerObject::decode(test.bytes.as_slice()).assert_err(test.err(), i);
	}
}