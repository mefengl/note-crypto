/**
 * RSA 公钥密码系统和签名算法实现模块
 * 
 * RSA（Rivest-Shamir-Adleman）是最早的也是最广泛使用的公钥密码系统之一，
 * 其安全性基于大整数质因数分解的计算困难性。RSA可用于加密、数字签名和密钥交换。
 * 
 * 本模块主要实现RSA的数字签名验证功能，支持两种签名方案：
 * 1. RSASSA-PKCS1-v1.5：传统的RSA签名方案
 * 2. RSASSA-PSS：更现代、更安全的带概率填充的RSA签名方案
 * 
 * RSA的安全性取决于密钥长度，在实际应用中，推荐使用2048位或更长的密钥。
 */

import { bigIntFromBytes, concatenateBytes, DynamicBuffer } from "@oslojs/binary";
import { constantTimeEqual } from "../subtle/index.js";
import {
	ASN1BitString,
	ASN1EncodableSequence,
	ASN1Integer,
	ASN1Null,
	ASN1ObjectIdentifier,
	ASN1OctetString,
	ASN1UniversalType,
	encodeASN1,
	encodeObjectIdentifier,
	parseASN1NoLeftoverBytes,
	type ASN1Value
} from "@oslojs/asn1";
import type { HashAlgorithm } from "../hash/index.js";

/**
 * 验证RSASSA-PKCS1-v1.5签名
 * 
 * PKCS#1 v1.5签名是一种传统的RSA签名方案，广泛用于TLS、PGP等协议。
 * 虽然PKCS#1 v1.5在理论上存在一些弱点，但在实践中仍然被广泛使用。
 * 
 * 验证过程：
 * 1. 将签名值s转换为整数
 * 2. 计算m = s^e mod n
 * 3. 将m转换为EM（编码消息）
 * 4. 验证EM的格式是否正确
 * 5. 验证EM中的哈希值是否与给定的哈希值匹配
 * 
 * @param publicKey RSA公钥（含模数n和公钥指数e）
 * @param hashObjectIdentifier 哈希算法的ASN.1对象标识符
 * @param hashed 消息的哈希值
 * @param signature 待验证的签名
 * @returns 签名是否有效
 */
export function verifyRSASSAPKCS1v15Signature(
	publicKey: RSAPublicKey,
	hashObjectIdentifier: string,
	hashed: Uint8Array,
	signature: Uint8Array
): boolean {
	// 将签名转换为大整数
	const s = bigIntFromBytes(signature);
	
	// 计算m = s^e mod n（RSA验证的核心步骤）
	const m = powmod(s, publicKey.e, publicKey.n);
	
	// 将m转换回字节数组，这就是编码消息EM
	const em = new Uint8Array(Math.ceil((publicKey.n.toString(2).length - 1) / 8));
	for (let i = 0; i < em.byteLength; i++) {
		em[i] = Number((m >> BigInt((em.byteLength - i - 1) * 8)) & 0xffn);
	}
	
	// 创建哈希值的ASN.1 DER编码
	// 这是PKCS#1 v1.5签名格式的一部分，包含哈希算法标识和哈希值
	const t = encodeASN1(
		new ASN1EncodableSequence([
			new ASN1EncodableSequence([
				new ASN1ObjectIdentifier(encodeObjectIdentifier(hashObjectIdentifier)),
				new ASN1Null()
			]),
			new ASN1OctetString(hashed)
		])
	);
	
	// 检查EM长度是否足够（必须能容纳填充和T）
	if (em.byteLength < t.byteLength + 11) {
		return false;
	}
	
	// 创建PKCS#1 v1.5格式的填充（一系列0xFF字节）
	const ps = new Uint8Array(em.byteLength - t.byteLength - 3).fill(0xff);
	
	// 创建期望的编码消息格式：0x00 0x01 PS 0x00 T
	const emPrime = new DynamicBuffer(0);
	emPrime.writeByte(0x00); // 起始字节
	emPrime.writeByte(0x01); // 块类型（01表示私钥操作）
	emPrime.write(ps);       // 填充字符串
	emPrime.writeByte(0x00); // 分隔符
	emPrime.write(t);        // 编码的哈希值
	
	// 以恒定时间方式比较实际的EM和期望的EM
	// 这是为了防止基于时间的侧信道攻击
	return constantTimeEqual(em, emPrime.bytes());
}

/**
 * 验证RSASSA-PSS签名
 * 
 * PSS（Probabilistic Signature Scheme，概率签名方案）是一种更现代、更安全的RSA签名方案，
 * 它使用随机填充和掩码生成函数（MGF），提供可证明的安全性。
 * 
 * 验证过程：
 * 1. 将签名值s转换为整数
 * 2. 检查s是否在有效范围内
 * 3. 计算m = s^e mod n
 * 4. 验证EM（编码消息）的格式
 * 5. 从EM中恢复盐值并验证哈希值
 * 
 * @param publicKey RSA公钥
 * @param MessageHashAlgorithm 用于哈希消息的算法
 * @param MGF1HashAlgorithm 用于掩码生成函数的哈希算法
 * @param saltLength 盐值长度（字节）
 * @param hashed 消息的哈希值
 * @param signature 待验证的签名
 * @returns 签名是否有效
 */
export function verifyRSASSAPSSSignature(
	publicKey: RSAPublicKey,
	MessageHashAlgorithm: HashAlgorithm,
	MGF1HashAlgorithm: HashAlgorithm,
	saltLength: number,
	hashed: Uint8Array,
	signature: Uint8Array
): boolean {
	// 将签名转换为大整数
	const s = bigIntFromBytes(signature);
	
	// 检查s是否在有效范围内（0 ≤ s < n）
	if (s < 0 || s >= publicKey.n) {
		return false;
	}
	
	// 计算m = s^e mod n（RSA验证的核心步骤）
	const m = powmod(s, publicKey.e, publicKey.n);
	
	// 计算允许的最大位长
	const maximalEMBits = publicKey.n.toString(2).length - 1;
	
	// 将m转换回字节数组，这就是编码消息EM
	const em = new Uint8Array(Math.ceil(maximalEMBits / 8));
	for (let i = 0; i < em.byteLength; i++) {
		em[i] = Number((m >> BigInt((em.byteLength - i - 1) * 8)) & 0xffn);
	}
	
	// 检查EM长度是否足够（必须能容纳哈希值、盐值和其他字段）
	if (em.byteLength < hashed.byteLength + saltLength + 2) {
		return false;
	}
	
	// 检查EM的最后一个字节是否为0xBC（PSS的结束标记）
	if (em[em.byteLength - 1] !== 0xbc) {
		return false;
	}
	
	// 提取DB（数据块）和H（哈希值）
	const db = em.slice(0, em.byteLength - hashed.byteLength - 1);
	const h = em.slice(em.byteLength - hashed.byteLength - 1, em.byteLength - 1);
	
	// 检查EM的最左侧比特是否为0（PSS格式要求）
	if (db[0] >> (8 - (8 * em.byteLength - maximalEMBits)) !== 0) {
		return false;
	}
	
	// 使用MGF1生成DB掩码
	const dbMask = mgf1(MGF1HashAlgorithm, h, em.byteLength - hashed.byteLength - 1);
	
	// 对DB进行异或解密
	for (let i = 0; i < db.byteLength; i++) {
		db[i] ^= dbMask[i];
	}
	
	// 将DB左侧的(8emLen - emBits)比特设置为0
	for (let i = 0; i < Math.floor((em.byteLength - hashed.byteLength - 1) / 8); i++) {
		db[i] = 0;
	}
	db[Math.floor((em.byteLength - hashed.byteLength - 1) / 8)] &=
		(1 << (8 - ((em.byteLength - hashed.byteLength - 1) % 8))) - 1;
	
	// 提取盐值
	const salt = db.slice(db.byteLength - saltLength);
	
	// 根据规范重建M'
	const mPrime = new DynamicBuffer(8 + hashed.byteLength + saltLength);
	mPrime.write(new Uint8Array([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])); // 8个0字节
	mPrime.write(hashed);  // 消息哈希
	mPrime.write(salt);    // 盐值
	
	// 计算H' = Hash(M')
	const hPrimeHash = new MessageHashAlgorithm();
	hPrimeHash.update(mPrime.bytes());
	
	// 比较H和H'
	return constantTimeEqual(h, hPrimeHash.digest());
}

/**
 * RSA公钥类
 * 
 * 包含RSA公钥的两个关键组件：
 * - n：模数（两个大素数的乘积）
 * - e：公钥指数（通常为65537）
 */
export class RSAPublicKey {
	/**
	 * 模数n，RSA密钥的主要安全参数
	 * 通常为1024位、2048位、3072位或4096位
	 */
	public n: bigint;
	
	/**
	 * 公钥指数e，通常选取较小的费马素数
	 * 最常用的值是65537（0x10001）
	 */
	public e: bigint;

	/**
	 * 构造RSA公钥
	 * 
	 * @param n 模数n
	 * @param e 公钥指数e
	 */
	constructor(n: bigint, e: bigint) {
		this.n = n;
		this.e = e;
	}

	/**
	 * 将RSA公钥编码为PKCS#1格式
	 * 
	 * PKCS#1格式是RSA公钥的简单ASN.1表示：
	 * RSAPublicKey ::= SEQUENCE {
	 *   modulus           INTEGER,  -- n
	 *   publicExponent    INTEGER   -- e
	 * }
	 * 
	 * @returns PKCS#1格式的DER编码公钥
	 */
	public encodePKCS1(): Uint8Array {
		const asn1 = new ASN1EncodableSequence([new ASN1Integer(this.n), new ASN1Integer(this.e)]);
		return encodeASN1(asn1);
	}

	/**
	 * 将RSA公钥编码为PKIX（X.509）格式
	 * 
	 * PKIX是更通用的公钥格式，用于X.509证书：
	 * SubjectPublicKeyInfo ::= SEQUENCE {
	 *   algorithm         AlgorithmIdentifier,
	 *   subjectPublicKey  BIT STRING
	 * }
	 * 
	 * @returns PKIX格式的DER编码公钥
	 */
	public encodePKIX(): Uint8Array {
		// 创建算法标识符（rsaEncryption OID和NULL参数）
		const algorithmIdentifier = new ASN1EncodableSequence([
			new ASN1ObjectIdentifier(encodeObjectIdentifier("1.2.840.113549.1.1.1")),
			new ASN1Null()
		]);
		
		// 获取PKCS#1编码的公钥
		const encoded = this.encodePKCS1();
		
		// 创建完整的SubjectPublicKeyInfo结构
		const subjectPublicKey = new ASN1BitString(encoded, encoded.byteLength * 8);
		const subjectPublicKeyInfo = new ASN1EncodableSequence([algorithmIdentifier, subjectPublicKey]);
		
		return encodeASN1(subjectPublicKeyInfo);
	}
}

/**
 * 从PKCS#1格式解码RSA公钥
 * 
 * @param pkcs1 PKCS#1格式的DER编码公钥
 * @returns RSA公钥对象
 * @throws 如果解码失败
 */
export function decodePKCS1RSAPublicKey(pkcs1: Uint8Array): RSAPublicKey {
	try {
		const asn1PublicKey = parseASN1NoLeftoverBytes(pkcs1).sequence();
		return new RSAPublicKey(
			asn1PublicKey.at(0).integer().value,
			asn1PublicKey.at(1).integer().value
		);
	} catch {
		throw new Error("Invalid public key");
	}
}

/**
 * 从PKIX（X.509）格式解码RSA公钥
 * 
 * @param pkix PKIX格式的DER编码公钥
 * @returns RSA公钥对象
 * @throws 如果解码失败或公钥不是RSA类型
 */
export function decodePKIXRSAPublicKey(pkix: Uint8Array): RSAPublicKey {
	let asn1Algorithm: ASN1ObjectIdentifier;
	let asn1Parameter: ASN1Value;
	let asn1PublicKey: ASN1BitString;
	
	try {
		// 解析SubjectPublicKeyInfo结构
		const asn1SubjectPublicKeyInfo = parseASN1NoLeftoverBytes(pkix).sequence();
		const asn1AlgorithmIdentifier = asn1SubjectPublicKeyInfo.at(0).sequence();
		asn1Algorithm = asn1AlgorithmIdentifier.at(0).objectIdentifier();
		asn1Parameter = asn1AlgorithmIdentifier.at(1);
		asn1PublicKey = asn1SubjectPublicKeyInfo.at(1).bitString();
	} catch {
		throw new Error("Failed to parse SubjectPublicKeyInfo");
	}
	
	// 验证算法标识符是否为RSA
	// rsaEncryption OID: 1.2.840.113549.1.1.1
	if (!asn1Algorithm.is("1.2.840.113549.1.1.1")) {
		throw new Error("Invalid public key OID");
	}
	
	// 验证参数是否为NULL
	if (asn1Parameter.universalType() !== ASN1UniversalType.Null) {
		throw new Error("Invalid public key");
	}
	
	try {
		// 解码PKCS#1格式的公钥
		return decodePKCS1RSAPublicKey(asn1PublicKey.bytes);
	} catch {
		throw new Error("Invalid public key");
	}
}

/**
 * 常用哈希算法的对象标识符（OID）
 * 这些OID用于在签名算法中标识使用的哈希函数
 */
// SHA-1哈希算法的OID（不推荐用于安全应用）
export const sha1ObjectIdentifier = "1.3.14.3.2.26";
// SHA-224哈希算法的OID
export const sha224ObjectIdentifier = "2.16.840.1.101.3.4.2.4";
// SHA-256哈希算法的OID
export const sha256ObjectIdentifier = "2.16.840.1.101.3.4.2.1";
// SHA-384哈希算法的OID
export const sha384ObjectIdentifier = "2.16.840.1.101.3.4.2.2";
// SHA-512哈希算法的OID
export const sha512ObjectIdentifier = "2.16.840.1.101.3.4.2.3";

/**
 * MGF1掩码生成函数
 * 
 * PSS签名方案中使用的标准掩码生成函数，基于哈希函数。
 * MGF1可以生成任意长度的字节序列，用于PSS中的数据掩码。
 * 
 * @param Hash 哈希算法构造函数
 * @param Z 种子值
 * @param l 需要生成的掩码长度
 * @returns 生成的掩码
 */
function mgf1(Hash: HashAlgorithm, Z: Uint8Array, l: number): Uint8Array {
	let t = new Uint8Array();
	let counter = 0;
	
	// 生成足够长度的输出
	while (t.byteLength < l) {
		// 将计数器转换为4字节（大端序）
		const counterBytes = new Uint8Array(4);
		for (let j = 0; j < counterBytes.byteLength; j++) {
			counterBytes[j] = Number((counter >> ((counterBytes.byteLength - j - 1) * 8)) & 0xff);
		}
		
		// 计算哈希：Hash(Z || counter)
		const zcHash = new Hash();
		zcHash.update(Z);
		zcHash.update(counterBytes);
		
		// 连接到结果中
		t = concatenateBytes(t, zcHash.digest());
		counter++;
	}
	
	// 截取所需长度
	return t.slice(0, l);
}

/**
 * 模幂运算（x^y mod p）
 * 
 * 使用快速幂算法（平方-乘）计算大整数的模幂，
 * 这是RSA加密和解密的核心运算。
 * 
 * @param x 底数
 * @param y 指数
 * @param p 模数
 * @returns x^y mod p的结果
 */
function powmod(x: bigint, y: bigint, p: bigint): bigint {
	let res = 1n;      // 初始化结果
	x = x % p;         // 确保x小于p
	
	// 快速幂算法
	while (y > 0) {
		// 如果y的最低位是1，则结果乘以当前的x
		if (y % 2n === 1n) {
			res = euclideanMod(res * x, p);
		}
		
		// y右移一位（相当于除以2）
		y = y >> 1n;
		
		// x平方
		x = euclideanMod(x * x, p);
	}
	
	return res;
}

/**
 * 欧几里得模运算
 * 
 * 确保模运算结果为非负数，与JavaScript的%运算符不同，
 * JavaScript的%运算符对负数取模会得到负数结果。
 * 
 * @param x 被除数
 * @param y 除数
 * @returns 非负的模运算结果
 */
function euclideanMod(x: bigint, y: bigint): bigint {
	const r = x % y;
	// 如果结果为负数，加上模数使其变为非负
	if (r < 0n) {
		return r + y;
	}
	return r;
}
