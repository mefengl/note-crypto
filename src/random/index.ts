import { bigIntFromBytes } from "@oslojs/binary";

export function random(): number {
	const buffer = new ArrayBuffer(8);
	const bytes = crypto.getRandomValues(new Uint8Array(buffer));

	// sets the exponent value (11 bits) to 01111111111 (1023)
	// since the bias is 1023 (2 * (11 - 1) - 1), 1023 - 1023 = 0
	// 2^0 * (1 + [52 bit number between 0-1]) = number between 1-2
	bytes[0] = 63;
	bytes[1] = bytes[1]! | 240;

	return new DataView(buffer).getFloat64(0) - 1;
}

export function generateRandomInteger(max: bigint): bigint {
	if (max < 2) {
		throw new Error("Argument 'max' must be a positive integer");
	}
	const inclusiveMaxBitLength = (max - 1n).toString(2).length;
	const shift = inclusiveMaxBitLength % 8;
	const bytes = new Uint8Array(Math.ceil(inclusiveMaxBitLength / 8));

	crypto.getRandomValues(bytes);

	// This zeroes bits that can be ignored to increase the chance `result` < `max`.
	// For example, if `max` can be represented with 10 bits, the leading 6 bits of the random 16 bits (2 bytes) can be ignored.
	if (shift !== 0) {
		bytes[0] &= (1 << shift) - 1;
	}
	let result = bigIntFromBytes(bytes);
	while (result >= max) {
		crypto.getRandomValues(bytes);
		if (shift !== 0) {
			bytes[0] &= (1 << shift) - 1;
		}
		result = bigIntFromBytes(bytes);
	}
	return result;
}

export function generateRandomIntegerNumber(max: number): number {
	if (max < 2 || max > Number.MAX_SAFE_INTEGER) {
		throw new Error("Argument 'max' must be a positive integer");
	}
	return Number(generateRandomInteger(BigInt(max)));
}

export function generateRandomString(length: number, alphabet: string): string {
	let result = "";
	for (let i = 0; i < length; i++) {
		result += alphabet[generateRandomIntegerNumber(alphabet.length)];
	}
	return result;
}

export type AlphabetPattern = "a-z" | "A-Z" | "0-9" | "-" | "_";

export function alphabet(...patterns: AlphabetPattern[]): string {
	const patternSet = new Set<AlphabetPattern>(patterns);
	let result = "";
	for (const pattern of patternSet) {
		if (pattern === "a-z") {
			result += "abcdefghijklmnopqrstuvwxyz";
		} else if (pattern === "A-Z") {
			result += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
		} else if (pattern === "0-9") {
			result += "0123456789";
		} else {
			result += pattern;
		}
	}
	return result;
}
