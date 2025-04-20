/**
 * ECDSA (椭圆曲线数字签名算法) 实现模块
 * 
 * ECDSA是基于椭圆曲线密码学的数字签名算法，相比传统RSA签名，
 * 在相同安全强度下具有密钥较短、计算速度较快、带宽占用较小等优点。
 * 
 * ECDSA广泛应用于：
 * 1. TLS/SSL安全通信
 * 2. 比特币、以太坊等区块链技术
 * 3. 安全启动和代码签名
 * 4. 智能卡和物联网设备
 * 
 * 本模块实现了ECDSA的验证算法、密钥和签名的编码解码方法，
 * 支持多种标准格式（如SEC1、PKIX、IEEE P1363等）。
 */
import { ECDSAPoint } from "./curve.js";
import { euclideanMod, inverseMod, tonelliShanks } from "./math.js";
import { bigIntBytes, bigIntFromBytes } from "@oslojs/binary";
import {
	ASN1BitString,
	ASN1EncodableSequence,
	ASN1Integer,
	ASN1ObjectIdentifier,
	encodeASN1,
	encodeObjectIdentifier,
	parseASN1NoLeftoverBytes
} from "@oslojs/asn1";
import type { ECDSANamedCurve } from "./curve.js";

/**
 * 验证ECDSA签名
 * 
 * ECDSA签名验证算法步骤：
 * 1. 验证公钥点Q在曲线上
 * 2. 验证n*Q = O（n是曲线阶）
 * 3. 验证签名值r和s在范围[1, n-1]内
 * 4. 计算e = HASH(消息)
 * 5. 计算w = s^(-1) mod n
 * 6. 计算u1 = e*w mod n 和 u2 = r*w mod n
 * 7. 计算点(x,y) = u1*G + u2*Q
 * 8. 验证r ≡ x (mod n)
 * 
 * @param publicKey ECDSA公钥
 * @param hash 消息哈希值
 * @param signature ECDSA签名
 * @returns 如果签名有效则返回true，否则返回false
 */
export function verifyECDSASignature(
	publicKey: ECDSAPublicKey,
	hash: Uint8Array,
	signature: ECDSASignature
): boolean {
	// 步骤1: 提取公钥点并验证其在曲线上
	const q = new ECDSAPoint(publicKey.x, publicKey.y);
	if (!publicKey.curve.isOnCurve(q)) {
		return false;
	}
	
	// 步骤2: 验证n*Q = O（公钥是曲线子群的成员）
	if (publicKey.curve.multiply(publicKey.curve.n, q) !== null) {
		return false;
	}
	
	// 步骤3: 使用消息哈希的前curve.size字节作为e
	const e = hash.slice(0, publicKey.curve.size);
	
	// 步骤4: 计算u1 = e * s^(-1) mod n
	const u1 = euclideanMod(
		bigIntFromBytes(e) * inverseMod(signature.s, publicKey.curve.n),
		publicKey.curve.n
	);
	
	// 步骤5: 计算u1*G
	const u1G = publicKey.curve.multiply(u1, publicKey.curve.g);
	if (u1G === null) {
		return false;
	}
	
	// 步骤6: 计算u2 = r * s^(-1) mod n
	const u2 = euclideanMod(
		signature.r * inverseMod(signature.s, publicKey.curve.n),
		publicKey.curve.n
	);
	
	// 步骤7: 计算u2*Q
	const u2Q = publicKey.curve.multiply(u2, q);
	if (u2Q === null) {
		return false;
	}
	
	// 步骤8: 计算点(x,y) = u1*G + u2*Q
	const coord1 = publicKey.curve.add(u1G, u2Q);
	if (coord1 === null) {
		return false;
	}
	
	// 步骤9: 验证r ≡ x (mod n)
	return euclideanMod(signature.r, publicKey.curve.n) === coord1.x;
}

/**
 * ECDSA公钥类
 * 
 * 包含曲线参数和公钥点坐标，并提供多种编码方法。
 */
export class ECDSAPublicKey {
	/**
	 * 公钥所在的命名曲线
	 * 包含曲线参数和标识符
	 */
	public curve: ECDSANamedCurve;
	
	/**
	 * 公钥点的X坐标
	 */
	public x: bigint;
	
	/**
	 * 公钥点的Y坐标
	 */
	public y: bigint;

	/**
	 * 创建ECDSA公钥
	 * 
	 * @param curve 椭圆曲线参数
	 * @param x 公钥点X坐标
	 * @param y 公钥点Y坐标
	 */
	constructor(curve: ECDSANamedCurve, x: bigint, y: bigint) {
		this.curve = curve;
		this.x = x;
		this.y = y;
	}

	/**
	 * 检查公钥是否使用指定的曲线
	 * 
	 * @param curve 要检查的曲线
	 * @returns 如果公钥使用指定曲线则返回true
	 */
	public isCurve(curve: ECDSANamedCurve): boolean {
		return this.curve.objectIdentifier === curve.objectIdentifier;
	}

	/**
	 * 编码为SEC1未压缩格式
	 * 
	 * 未压缩格式以0x04开头，后跟X和Y坐标的完整字节表示。
	 * 格式：04 || X || Y
	 * 
	 * @returns SEC1未压缩编码的公钥字节数组
	 */
	public encodeSEC1Uncompressed(): Uint8Array {
		const bytes = new Uint8Array(1 + this.curve.size * 2);
		bytes[0] = 0x04; // 未压缩格式标记
		const xBytes = bigIntBytes(this.x);
		const yBytes = bigIntBytes(this.y);
		bytes.set(xBytes, 1 + this.curve.size - xBytes.byteLength);
		bytes.set(yBytes, 1 + this.curve.size * 2 - yBytes.byteLength);
		return bytes;
	}

	/**
	 * 编码为SEC1压缩格式
	 * 
	 * 压缩格式只存储X坐标，并使用前缀表示Y坐标的奇偶性：
	 * - 0x02：Y坐标为偶数
	 * - 0x03：Y坐标为奇数
	 * 
	 * @returns SEC1压缩编码的公钥字节数组
	 */
	public encodeSEC1Compressed(): Uint8Array {
		const bytes = new Uint8Array(1 + this.curve.size);
		if (this.y % 2n === 0n) {
			bytes[0] = 0x02; // Y为偶数
		} else {
			bytes[0] = 0x03; // Y为奇数
		}
		const xBytes = bigIntBytes(this.x);
		bytes.set(xBytes, 1 + this.curve.size - xBytes.byteLength);
		return bytes;
	}

	/**
	 * 编码为PKIX（X.509）未压缩格式
	 * 
	 * PKIX格式是标准X.509证书中使用的格式，包含：
	 * 1. 算法标识符（椭圆曲线加密）
	 * 2. 曲线标识符
	 * 3. 未压缩的公钥数据
	 * 
	 * @returns PKIX未压缩编码的公钥字节数组（ASN.1 DER格式）
	 */
	public encodePKIXUncompressed(): Uint8Array {
		// 算法标识符序列：EC公钥算法OID + 特定曲线OID
		const algorithmIdentifier = new ASN1EncodableSequence([
			new ASN1ObjectIdentifier(encodeObjectIdentifier("1.2.840.10045.2.1")), // EC公钥算法OID
			new ASN1ObjectIdentifier(encodeObjectIdentifier(this.curve.objectIdentifier)) // 曲线OID
		]);
		
		// 编码为未压缩SEC1格式
		const encoded = this.encodeSEC1Uncompressed();
		
		// 创建比特串结构
		const subjectPublicKey = new ASN1BitString(encoded, encoded.byteLength * 8);
		
		// 创建完整的SubjectPublicKeyInfo结构
		const subjectPublicKeyInfo = new ASN1EncodableSequence([algorithmIdentifier, subjectPublicKey]);
		
		// 编码为ASN.1 DER格式
		return encodeASN1(subjectPublicKeyInfo);
	}

	/**
	 * 编码为PKIX（X.509）压缩格式
	 * 
	 * 与未压缩PKIX格式类似，但使用压缩的SEC1公钥表示。
	 * 
	 * @returns PKIX压缩编码的公钥字节数组（ASN.1 DER格式）
	 */
	public encodePKIXCompressed(): Uint8Array {
		const algorithmIdentifier = new ASN1EncodableSequence([
			new ASN1ObjectIdentifier(encodeObjectIdentifier("1.2.840.10045.2.1")),
			new ASN1ObjectIdentifier(encodeObjectIdentifier(this.curve.objectIdentifier))
		]);
		
		// 使用压缩SEC1格式
		const encoded = this.encodeSEC1Compressed();
		const subjectPublicKey = new ASN1BitString(encoded, encoded.byteLength * 8);
		const subjectPublicKeyInfo = new ASN1EncodableSequence([algorithmIdentifier, subjectPublicKey]);
		return encodeASN1(subjectPublicKeyInfo);
	}
}

/**
 * 解码SEC1格式的ECDSA公钥
 * 
 * 支持解码以下格式：
 * - 0x04：未压缩格式（包含完整的X和Y坐标）
 * - 0x02：压缩格式，Y坐标为偶数
 * - 0x03：压缩格式，Y坐标为奇数
 * 
 * 对于压缩格式，需要通过椭圆曲线方程y² = x³ + ax + b求解Y坐标
 * 
 * @param curve 椭圆曲线参数
 * @param bytes SEC1编码的公钥字节数组
 * @returns 解码后的ECDSA公钥
 * @throws 如果输入无效则抛出错误
 */
export function decodeSEC1PublicKey(curve: ECDSANamedCurve, bytes: Uint8Array): ECDSAPublicKey {
	if (bytes.byteLength < 1) {
		throw new Error("Invalid public key");
	}
	
	// 处理未压缩格式（0x04）
	if (bytes[0] === 0x04) {
		if (bytes.byteLength !== curve.size * 2 + 1) {
			throw new Error("Invalid public key");
		}
		const x = bigIntFromBytes(bytes.slice(1, curve.size + 1));
		const y = bigIntFromBytes(bytes.slice(curve.size + 1));
		return new ECDSAPublicKey(curve, x, y);
	}
	
	// 处理压缩格式：Y坐标为偶数（0x02）
	if (bytes[0] === 0x02) {
		if (bytes.byteLength !== curve.size + 1) {
			throw new Error("Invalid public key");
		}
		const x = bigIntFromBytes(bytes.slice(1));
		
		// 通过椭圆曲线方程计算y²: y² = x³ + ax + b
		const y2 = euclideanMod(x ** 3n + curve.a * x + curve.b, curve.p);
		
		// 使用Tonelli-Shanks算法求解y
		const y = tonelliShanks(y2, curve.p);
		
		// 选择偶数的y值
		if (y % 2n === 0n) {
			return new ECDSAPublicKey(curve, x, y);
		}
		
		// 如果计算出的y是奇数，则取其补值
		return new ECDSAPublicKey(curve, x, curve.p - y);
	}
	
	// 处理压缩格式：Y坐标为奇数（0x03）
	if (bytes[0] === 0x03) {
		if (bytes.byteLength !== curve.size + 1) {
			throw new Error("Invalid public key");
		}
		const x = bigIntFromBytes(bytes.slice(1));
		
		// 通过椭圆曲线方程计算y²
		const y2 = euclideanMod(x ** 3n + curve.a * x + curve.b, curve.p);
		
		// 使用Tonelli-Shanks算法求解y
		const y = tonelliShanks(y2, curve.p);
		
		// 选择奇数的y值
		if (y % 2n === 1n) {
			return new ECDSAPublicKey(curve, x, y);
		}
		
		// 如果计算出的y是偶数，则取其补值
		return new ECDSAPublicKey(curve, x, curve.p - y);
	}
	
	throw new Error("Unknown encoding format");
}

/**
 * ECDSA签名类
 * 
 * 包含签名的两个值r和s，并提供多种编码方法。
 * 在ECDSA中：
 * - r值：签名时临时密钥对应的点的x坐标
 * - s值：包含消息哈希、私钥和临时密钥的计算结果
 */
export class ECDSASignature {
	/**
	 * 签名的r值
	 * 在ECDSA算法中，r是临时密钥生成的点的x坐标
	 */
	public r: bigint;
	
	/**
	 * 签名的s值
	 * s = (z + r·dA) / k mod n
	 * 其中z是消息哈希，dA是私钥，k是临时密钥
	 */
	public s: bigint;

	/**
	 * 创建ECDSA签名
	 * 
	 * @param r 签名的r值
	 * @param s 签名的s值
	 * @throws 如果r或s小于1则抛出错误
	 */
	constructor(r: bigint, s: bigint) {
		if (r < 1n || s < 1n) {
			throw new TypeError("Invalid signature");
		}
		this.r = r;
		this.s = s;
	}

	/**
	 * 编码为IEEE P1363格式
	 * 
	 * IEEE P1363格式是r和s值的简单连接，每个值填充到曲线字节大小：
	 * r || s
	 * 
	 * @param curve 椭圆曲线参数
	 * @returns IEEE P1363编码的签名字节数组
	 * @throws 如果r或s值太大而无法编码则抛出错误
	 */
	public encodeIEEEP1363(curve: ECDSANamedCurve): Uint8Array {
		const rs = new Uint8Array(curve.size * 2);
		
		const rBytes = bigIntBytes(this.r);
		if (rBytes.byteLength > curve.size) {
			throw new Error("'r' is too large");
		}
		
		const sBytes = bigIntBytes(this.s);
		if (sBytes.byteLength > curve.size) {
			throw new Error("'s' is too large");
		}
		
		// 填充r值
		rs.set(rBytes, curve.size - rBytes.byteLength);
		
		// 填充s值
		rs.set(sBytes, curve.size * 2 - sBytes.byteLength);
		
		return rs;
	}

	/**
	 * 编码为PKIX（ASN.1 DER）格式
	 * 
	 * PKIX格式是标准的ASN.1结构，包含两个整数r和s：
	 * SEQUENCE {
	 *   r INTEGER,
	 *   s INTEGER
	 * }
	 * 
	 * @returns PKIX编码的签名字节数组（ASN.1 DER格式）
	 */
	public encodePKIX(): Uint8Array {
		const asn1 = new ASN1EncodableSequence([new ASN1Integer(this.r), new ASN1Integer(this.s)]);
		return encodeASN1(asn1);
	}
}

/**
 * 解码IEEE P1363格式的ECDSA签名
 * 
 * IEEE P1363格式是r和s值的简单连接，每个值具有曲线字节大小
 * 
 * @param curve 椭圆曲线参数
 * @param bytes IEEE P1363编码的签名字节数组
 * @returns 解码后的ECDSA签名
 * @throws 如果签名大小无效则抛出错误
 */
export function decodeIEEEP1363ECDSASignature(
	curve: ECDSANamedCurve,
	bytes: Uint8Array
): ECDSASignature {
	if (bytes.byteLength !== curve.size * 2) {
		throw new Error("Failed to decode signature: Invalid signature size");
	}
	
	// 前半部分是r值
	const r = bigIntFromBytes(bytes.slice(0, curve.size));
	
	// 后半部分是s值
	const s = bigIntFromBytes(bytes.slice(curve.size));
	
	return new ECDSASignature(r, s);
}

/**
 * 解码PKIX（ASN.1 DER）格式的ECDSA签名
 * 
 * PKIX格式是标准的ASN.1结构：
 * SEQUENCE {
 *   r INTEGER,
 *   s INTEGER
 * }
 * 
 * @param der PKIX编码的签名字节数组（ASN.1 DER格式）
 * @returns 解码后的ECDSA签名
 * @throws 如果签名解码失败则抛出错误
 */
export function decodePKIXECDSASignature(der: Uint8Array): ECDSASignature {
	try {
		const sequence = parseASN1NoLeftoverBytes(der).sequence();
		return new ECDSASignature(sequence.at(0).integer().value, sequence.at(1).integer().value);
	} catch {
		throw new Error("Failed to decode signature");
	}
}

/**
 * 解码PKIX（X.509）格式的ECDSA公钥
 * 
 * PKIX格式是标准X.509证书中使用的格式：
 * SEQUENCE {
 *   SEQUENCE {                      // AlgorithmIdentifier
 *     OBJECT IDENTIFIER ecPublicKey // 1.2.840.10045.2.1
 *     OBJECT IDENTIFIER curveOid    // 特定曲线的OID
 *   }
 *   BIT STRING publicKey           // SEC1编码的公钥
 * }
 * 
 * @param bytes PKIX编码的公钥字节数组
 * @param curves 支持的椭圆曲线列表
 * @returns 解码后的ECDSA公钥
 * @throws 如果公钥解码失败或曲线不匹配则抛出错误
 */
export function decodePKIXECDSAPublicKey(
	bytes: Uint8Array,
	curves: ECDSANamedCurve[]
): ECDSAPublicKey {
	let algorithmIdentifierObjectIdentifier: ASN1ObjectIdentifier;
	let algorithmIdentifierParameter: ASN1ObjectIdentifier;
	let asn1PublicKey: ASN1BitString;
	
	try {
		// 解析整体结构
		const subjectPublicKeyInfo = parseASN1NoLeftoverBytes(bytes).sequence();
		
		// 解析算法标识符
		const algorithmIdentifier = subjectPublicKeyInfo.at(0).sequence();
		algorithmIdentifierObjectIdentifier = algorithmIdentifier.at(0).objectIdentifier();
		algorithmIdentifierParameter = algorithmIdentifier.at(1).objectIdentifier();
		
		// 获取公钥比特串
		asn1PublicKey = subjectPublicKeyInfo.at(1).bitString();
	} catch {
		throw new Error("Failed to decode elliptic curve public key");
	}
	
	// 验证是椭圆曲线公钥算法
	if (!algorithmIdentifierObjectIdentifier.is("1.2.840.10045.2.1")) {
		throw new Error("Invalid algorithm");
	}
	
	// 查找匹配的曲线
	for (const curve of curves) {
		if (algorithmIdentifierParameter.is(curve.objectIdentifier)) {
			// 使用SEC1解码器解码公钥数据
			return decodeSEC1PublicKey(curve, asn1PublicKey.bytes);
		}
	}
	
	throw new Error("No matching curves");
}
