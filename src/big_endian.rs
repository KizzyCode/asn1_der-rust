use std;

/// Decodes a big-endian encoded unsigned integer
pub fn decode(data: &[u8]) -> u64 {
	let mut value = 0;
	for i in 0 .. std::cmp::min(data.len(), std::mem::size_of::<u64>()) {
		value <<= 8;
		value |= data[i] as u64;
	}
	value
}


/// Encodes an unsigned integer using big-endian
pub fn encode(buffer: &mut[u8], mut value: u64) {
	for i in (0 .. std::cmp::min(buffer.len(), std::mem::size_of::<u64>())).rev() {
		buffer[i] = value as u8;
		value >>= 8;
	}
}