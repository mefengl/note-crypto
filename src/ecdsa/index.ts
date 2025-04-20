/**
 * ECDSA 椭圆曲线数字签名算法模块
 * 
 * ECDSA（Elliptic Curve Digital Signature Algorithm）是一种基于椭圆曲线密码学的数字签名算法，
 * 相比传统的RSA算法，它提供了相同安全强度下更小的密钥长度和签名长度。
 * 
 * ECDSA的主要特点：
 * 1. 基于椭圆曲线离散对数问题（ECDLP）的安全性
 * 2. 签名速度快，密钥和签名长度短
 * 3. 支持多种标准化曲线（NIST曲线、SECG曲线等）
 * 4. 广泛应用于TLS、比特币、以太坊等系统
 * 
 * 本模块提供了ECDSA的验证功能，包括各种标准曲线的实现和编解码工具。
 */

// 导出ECDSA核心功能和数据结构
export {
	// 解码IEEE P1363格式的ECDSA签名（R和S的连接）
	decodeIEEEP1363ECDSASignature,
	
	// 解码SEC1格式的ECDSA公钥（椭圆曲线点的压缩或非压缩表示）
	decodeSEC1PublicKey,
	
	// 解码PKIX（X.509）格式的ECDSA公钥
	decodePKIXECDSAPublicKey,
	
	// 解码PKIX（X.509）格式的ECDSA签名（ASN.1 DER编码）
	decodePKIXECDSASignature,
	
	// ECDSA公钥类型，包含曲线信息和公钥点坐标
	ECDSAPublicKey,
	
	// ECDSA签名类型，包含签名的R和S值
	ECDSASignature,
	
	// 验证ECDSA签名的函数
	verifyECDSASignature
} from "./ecdsa.js";

// 导出NIST（美国国家标准与技术研究院）标准曲线
export { 
	p192, // NIST P-192曲线，安全性约96位
	p224, // NIST P-224曲线，安全性约112位
	p256, // NIST P-256曲线，安全性约128位，最常用
	p384, // NIST P-384曲线，安全性约192位
	p521  // NIST P-521曲线，安全性约256位，最高安全强度
} from "./curve-nist.js";

// 导出SECG（Standards for Efficient Cryptography Group）标准曲线
export {
	secp192k1, // SEC曲线，192位，Koblitz曲线
	secp192r1, // SEC曲线，192位，随机曲线（等同于NIST P-192）
	secp224k1, // SEC曲线，224位，Koblitz曲线
	secp224r1, // SEC曲线，224位，随机曲线（等同于NIST P-224）
	secp256k1, // SEC曲线，256位，Koblitz曲线，在比特币和以太坊中广泛使用
	secp256r1, // SEC曲线，256位，随机曲线（等同于NIST P-256）
	secp384r1, // SEC曲线，384位，随机曲线（等同于NIST P-384）
	secp521r1  // SEC曲线，521位，随机曲线（等同于NIST P-521）
} from "./curve-sec.js";

// 导出椭圆曲线通用类型
export { ECDSANamedCurve } from "./curve.js";
