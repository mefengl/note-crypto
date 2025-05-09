/**
 * SECG (Standards for Efficient Cryptography Group) 标准椭圆曲线定义
 * 
 * 本文件定义了多条由 SECG 标准化的椭圆曲线参数。
 * 这些曲线广泛应用于各种密码学场景，特别是 ECDSA 数字签名。
 * 
 * 每条曲线都通过其实例化的 `ECDSANamedCurve` 类表示，包含了以下关键参数：
 * - p: 有限域的模数 (Prime modulus of the underlying finite field)
 * - a, b: 曲线方程 y² = x³ + ax + b 的系数 (Coefficients of the curve equation)
 * - gx, gy: 基点 G 的仿射坐标 (Affine coordinates (x, y) of the base point G)
 * - n: 基点 G 的阶 (Order of the base point G)
 * - h: 余因子 (Cofactor)
 * - size: 曲线参数的字节长度 (Size of curve parameters in bytes)
 * - oid: 对象标识符 (Object Identifier - OID)
 * 
 * 本文件包含以下曲线：
 * - Koblitz 曲线 (以 'k1' 结尾): 具有特定结构，有时可实现更高效的运算。
 *   - secp192k1
 *   - secp224k1
 *   - secp256k1 (在比特币和以太坊中广泛使用)
 * - 随机曲线 (以 'r1' 结尾): 参数看似随机生成。
 *   - secp192r1 (等同于 NIST P-192)
 *   - secp224r1 (等同于 NIST P-224)
 *   - secp256r1 (等同于 NIST P-256, 非常常用)
 *   - secp384r1 (等同于 NIST P-384)
 *   - secp521r1 (等同于 NIST P-521)
 * 
 * 这些参数都是标准的、公开的数值，确保了不同实现之间的互操作性。
 */
import { ECDSANamedCurve } from "./curve.js";

export const secp192k1 = new ECDSANamedCurve(
	0xfffffffffffffffffffffffffffffffffffffffeffffee37n,
	0x000000000000000000000000000000000000000000000000n,
	0x000000000000000000000000000000000000000000000003n,
	0xdb4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7dn,
	0x9b2f2f6d9c5628a7844163d015be86344082aa88d95e2f9dn,
	0xfffffffffffffffffffffffe26f2fc170f69466a74defd8dn,
	1n,
	24,
	"1.3.132.0.31"
);

export const secp192r1 = new ECDSANamedCurve(
	0xfffffffffffffffffffffffffffffffeffffffffffffffffn,
	0xfffffffffffffffffffffffffffffffefffffffffffffffcn,
	0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1n,
	0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012n,
	0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811n,
	0xffffffffffffffffffffffff99def836146bc9b1b4d22831n,
	1n,
	24,
	"1.2.840.10045.3.1.1"
);

export const secp224k1 = new ECDSANamedCurve(
	0xfffffffffffffffffffffffffffffffffffffffffffffffeffffe56dn,
	0x00000000000000000000000000000000000000000000000000000000n,
	0x00000000000000000000000000000000000000000000000000000005n,
	0xa1455b334df099df30fc28a169a467e9e47075a90f7e650eb6b7a45cn,
	0x7e089fed7fba344282cafbd6f7e319f7c0b0bd59e2ca4bdb556d61a5n,
	0x10000000000000000000000000001dce8d2ec6184caf0a971769fb1f7n,
	1n,
	28,
	"1.3.132.0.32"
);

export const secp224r1 = new ECDSANamedCurve(
	0xffffffffffffffffffffffffffffffff000000000000000000000001n,
	0xfffffffffffffffffffffffffffffffefffffffffffffffffffffffen,
	0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4n,
	0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21n,
	0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34n,
	0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3dn,
	1n,
	28,
	"1.3.132.0.33"
);

export const secp256k1 = new ECDSANamedCurve(
	0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn,
	0x0000000000000000000000000000000000000000000000000000000000000000n,
	0x0000000000000000000000000000000000000000000000000000000000000007n,
	0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
	0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
	0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n,
	1n,
	32,
	"1.3.132.0.10"
);

export const secp256r1 = new ECDSANamedCurve(
	0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn,
	0xffffffff00000001000000000000000000000000fffffffffffffffffffffffcn,
	0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn,
	0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
	0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n,
	0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n,
	1n,
	32,
	"1.2.840.10045.3.1.7"
);

export const secp384r1 = new ECDSANamedCurve(
	0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffffn,
	0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffcn,
	0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aefn,
	0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7n,
	0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5fn,
	0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973n,
	1n,
	48,
	"1.3.132.0.34"
);

export const secp521r1 = new ECDSANamedCurve(
	0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffn,
	0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffcn,
	0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00n,
	0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66n,
	0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650n,
	0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409n,
	1n,
	66,
	"1.3.132.0.35"
);
