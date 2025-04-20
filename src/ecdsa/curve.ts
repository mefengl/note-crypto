/**
 * 椭圆曲线密码学(ECC)的曲线实现
 * 
 * 椭圆曲线密码学是一种基于椭圆曲线数学的公钥密码系统。
 * 椭圆曲线是由方程 y² = x³ + ax + b（Weierstrass形式）描述的曲线，
 * 通过定义点的加法和标量乘法运算，形成了可用于密码学的群结构。
 * 
 * 本模块实现了用于ECDSA算法的椭圆曲线基本操作，包括：
 * 1. 点的加法和倍乘
 * 2. 标量乘法
 * 3. 点格式转换（仿射坐标与雅可比坐标）
 * 4. 曲线参数管理
 */
import { bigIntBytes } from "@oslojs/binary";
import { euclideanMod, inverseMod } from "./math.js";

/**
 * 椭圆曲线上的点（仿射坐标表示）
 * 
 * 表示椭圆曲线上的一个点，使用标准的仿射坐标系(x,y)
 */
export class ECDSAPoint {
	/**
	 * 点的X坐标
	 */
	public x: bigint;
	
	/**
	 * 点的Y坐标
	 */
	public y: bigint;
	
	/**
	 * 创建椭圆曲线点
	 * 
	 * @param x 点的X坐标
	 * @param y 点的Y坐标
	 */
	constructor(x: bigint, y: bigint) {
		this.x = x;
		this.y = y;
	}
}

/**
 * 椭圆曲线上的点（雅可比坐标表示）
 * 
 * 雅可比坐标表示使用三个坐标(X,Y,Z)表示点，其中仿射坐标可通过(x=X/Z²,y=Y/Z³)计算。
 * 雅可比坐标的主要优势是可以避免点加法和倍乘运算中的模逆运算，提高计算效率。
 */
class JacobianPoint {
	/**
	 * 雅可比坐标的X分量
	 */
	public x: bigint;
	
	/**
	 * 雅可比坐标的Y分量
	 */
	public y: bigint;
	
	/**
	 * 雅可比坐标的Z分量
	 * Z=0表示无穷远点(点群的单位元)
	 */
	public z: bigint;
	
	/**
	 * 创建雅可比坐标点
	 * 
	 * @param x 雅可比坐标的X分量
	 * @param y 雅可比坐标的Y分量
	 * @param z 雅可比坐标的Z分量
	 */
	constructor(x: bigint, y: bigint, z: bigint) {
		this.x = x;
		this.y = y;
		this.z = z;
	}
	
	/**
	 * 检查点是否为无穷远点
	 * 
	 * 无穷远点是椭圆曲线点群的单位元，在雅可比坐标中表示为(0:1:0)
	 * 
	 * @returns 如果点是无穷远点则返回true
	 */
	public isAtInfinity(): boolean {
		return this.x === 0n && this.y === 1n && this.z === 0n;
	}
}

/**
 * 命名椭圆曲线类
 * 
 * 表示一条标准化的椭圆曲线，包含完整的曲线参数和标识符。
 * 提供点运算、坐标转换等核心功能。
 */
export class ECDSANamedCurve {
	/**
	 * 曲线的模数p
	 * 椭圆曲线运算在模p的有限域上进行
	 */
	public p: bigint;
	
	/**
	 * 曲线方程参数a
	 * 曲线方程: y² = x³ + ax + b
	 */
	public a: bigint;
	
	/**
	 * 曲线方程参数b
	 * 曲线方程: y² = x³ + ax + b
	 */
	public b: bigint;
	
	/**
	 * 基点G
	 * 曲线的生成元点，所有其他点都可以通过G的标量乘法生成
	 */
	public g: ECDSAPoint;
	
	/**
	 * 基点G的阶n
	 * n*G = O（无穷远点），n是使基点G生成的循环子群的大小
	 */
	public n: bigint;
	
	/**
	 * 余因子h
	 * h = #E(Fp)/n，表示整个曲线点集大小与子群大小的比值
	 */
	public cofactor: bigint;
	
	/**
	 * 曲线参数的字节大小
	 * 影响密钥和签名的长度
	 */
	public size: number;
	
	/**
	 * 曲线的对象标识符(OID)
	 * 用于在各种标准中唯一标识此曲线
	 */
	public objectIdentifier: string;

	/**
	 * 创建命名椭圆曲线
	 * 
	 * @param p 模数p
	 * @param a 曲线参数a
	 * @param b 曲线参数b
	 * @param gx 基点G的x坐标
	 * @param gy 基点G的y坐标
	 * @param n 基点G的阶
	 * @param cofactor 余因子
	 * @param size 曲线参数的字节大小
	 * @param objectIdentifier 曲线的对象标识符
	 */
	constructor(
		p: bigint,
		a: bigint,
		b: bigint,
		gx: bigint,
		gy: bigint,
		n: bigint,
		cofactor: bigint,
		size: number,
		objectIdentifier: string
	) {
		this.p = p;
		this.a = a;
		this.b = b;
		this.g = new ECDSAPoint(gx, gy);
		this.n = n;
		this.cofactor = cofactor;
		this.size = size;
		this.objectIdentifier = objectIdentifier;
	}

	/**
	 * 在椭圆曲线上加两个点
	 * 
	 * 实现椭圆曲线的点加法：P + Q = R
	 * 
	 * @param point1 点P
	 * @param point2 点Q
	 * @returns 点P+Q，如果结果是无穷远点则返回null
	 */
	public add(point1: ECDSAPoint, point2: ECDSAPoint): ECDSAPoint | null {
		// 先转换为雅可比坐标以提高计算效率
		const jacobian1 = this.fromAffine(point1);
		const jacobian2 = this.fromAffine(point2);
		
		// 在雅可比坐标下进行加法运算，再转回仿射坐标
		return this.toAffine(this.addJacobian(jacobian1, jacobian2));
	}

	/**
	 * 在雅可比坐标下加两个点
	 * 
	 * 雅可比坐标下的点加法公式:
	 * 如果P = (X1,Y1,Z1), Q = (X2,Y2,Z2)
	 * 则P+Q = (X3,Y3,Z3)，其中:
	 * U1 = X1·Z2²
	 * U2 = X2·Z1²
	 * S1 = Y1·Z2³
	 * S2 = Y2·Z1³
	 * H = U2-U1
	 * R = S2-S1
	 * X3 = R²-H³-2U1H²
	 * Y3 = R(U1H²-X3)-S1H³
	 * Z3 = HZ1Z2
	 * 
	 * @param point1 雅可比坐标下的点P
	 * @param point2 雅可比坐标下的点Q
	 * @returns 雅可比坐标下的点P+Q
	 */
	private addJacobian(point1: JacobianPoint, point2: JacobianPoint): JacobianPoint {
		// 如果任一点是无穷远点，返回另一点
		if (point1.isAtInfinity()) {
			return point2;
		}
		if (point2.isAtInfinity()) {
			return point1;
		}
		
		// 计算Z1²和Z2²
		const point1zz = point1.z ** 2n;
		const point2zz = point2.z ** 2n;
		
		// 计算U1 = X1·Z2² 和 U2 = X2·Z1²
		const u1 = euclideanMod(point1.x * point2zz, this.p);
		const u2 = euclideanMod(point2.x * point1zz, this.p);
		
		// 计算S1 = Y1·Z2³ 和 S2 = Y2·Z1³
		const s1 = euclideanMod(point1.y * point2zz * point2.z, this.p);
		const s2 = euclideanMod(point2.y * point1zz * point1.z, this.p);
		
		// 如果U1 = U2，则点在同一垂直线上
		if (u1 === u2) {
			// 如果S1 != S2，则点是互为相反数的点，和为无穷远点
			if (s1 !== s2) {
				return pointAtInfinity();
			}
			// 如果S1 = S2，则点相同，需要使用点倍乘公式
			return this.doubleJacobian(point1);
		}
		
		// 计算H = U2-U1 和 R = S2-S1
		const h = u2 - u1;
		const r = s2 - s1;
		
		// 计算X3 = R²-H³-2U1H²
		const point3x = euclideanMod(r ** 2n - h ** 3n - 2n * u1 * h ** 2n, this.p);
		
		// 计算结果点的坐标
		const point3 = new JacobianPoint(
			point3x,
			// Y3 = R(U1H²-X3)-S1H³
			euclideanMod(r * (u1 * h ** 2n - point3x) - s1 * h ** 3n, this.p),
			// Z3 = HZ1Z2
			euclideanMod(h * point1.z * point2.z, this.p)
		);
		
		return point3;
	}

	/**
	 * 在椭圆曲线上将一个点加倍
	 * 
	 * 实现点倍乘公式：2P = P + P
	 * 
	 * @param point 要加倍的点P
	 * @returns 2P，如果结果是无穷远点则返回null
	 */
	public double(point: ECDSAPoint): ECDSAPoint | null {
		// 转换为雅可比坐标
		const jacobian = this.fromAffine(point);
		
		// 在雅可比坐标下进行倍乘运算，再转回仿射坐标
		return this.toAffine(this.doubleJacobian(jacobian));
	}

	/**
	 * 在雅可比坐标下将点加倍
	 * 
	 * 雅可比坐标下的点倍乘公式:
	 * 如果P = (X,Y,Z)，则2P = (X',Y',Z')，其中:
	 * S = 4XY²
	 * M = 3X²+aZ⁴  (a是曲线参数)
	 * X' = M²-2S
	 * Y' = M(S-X')-8Y⁴
	 * Z' = 2YZ
	 * 
	 * @param point 雅可比坐标下的点P
	 * @returns 雅可比坐标下的点2P
	 */
	private doubleJacobian(point: JacobianPoint): JacobianPoint {
		// 如果是无穷远点，倍乘结果仍为无穷远点
		if (point.isAtInfinity()) {
			return point;
		}
		
		// 如果Y坐标为0，则结果是无穷远点
		// (这对应于点P与其相反点-P相同的情况，即P在x轴上)
		if (point.y === 0n) {
			return pointAtInfinity();
		}
		
		// 计算S = 4XY²
		const s = euclideanMod(4n * point.x * point.y ** 2n, this.p);
		
		// 计算M = 3X²+aZ⁴
		const m = euclideanMod(3n * point.x ** 2n + this.a * point.z ** 4n, this.p);
		
		// 计算X' = M²-2S
		const resultx = euclideanMod(m ** 2n - 2n * s, this.p);
		
		// 计算结果点的坐标
		const result = new JacobianPoint(
			resultx,
			// Y' = M(S-X')-8Y⁴
			euclideanMod(m * (s - resultx) - 8n * point.y ** 4n, this.p),
			// Z' = 2YZ
			euclideanMod(2n * point.y * point.z, this.p)
		);
		
		return result;
	}

	/**
	 * 将雅可比坐标转换为仿射坐标
	 * 
	 * 转换公式:
	 * x = X/Z²
	 * y = Y/Z³
	 * 
	 * @param point 雅可比坐标点(X,Y,Z)
	 * @returns 仿射坐标点(x,y)，如果是无穷远点则返回null
	 */
	public toAffine(point: JacobianPoint): ECDSAPoint | null {
		// 无穷远点转换为null
		if (point.isAtInfinity()) {
			return null;
		}
		
		// 计算Z的逆元
		const inverseZ = inverseMod(point.z, this.p);
		const inverseZ2 = inverseZ ** 2n;
		
		// 转换坐标
		const affine = new ECDSAPoint(
			euclideanMod(point.x * inverseZ2, this.p),
			euclideanMod(point.y * inverseZ2 * inverseZ, this.p)
		);
		
		return affine;
	}

	/**
	 * 将仿射坐标转换为雅可比坐标
	 * 
	 * 转换公式:
	 * X = x
	 * Y = y
	 * Z = 1
	 * 
	 * @param point 仿射坐标点(x,y)
	 * @returns 雅可比坐标点(X,Y,Z)
	 */
	public fromAffine(point: ECDSAPoint): JacobianPoint {
		return new JacobianPoint(point.x, point.y, 1n);
	}

	/**
	 * 标量乘法：计算k*P
	 * 
	 * 使用双重加法链(Double-and-Add)算法实现标量乘法:
	 * 1. 将k表示为二进制
	 * 2. 对每一位，如果为1，则加上当前点；无论如何都将当前点加倍
	 * 
	 * 注：假设点已经在曲线上
	 * 
	 * @param k 标量值
	 * @param point 要乘的点P
	 * @returns k*P，如果结果是无穷远点则返回null
	 */
	public multiply(k: bigint, point: ECDSAPoint): ECDSAPoint | null {
		// 转换标量为字节数组
		const kBytes = bigIntBytes(k);
		const bitLength = k.toString(2).length;
		
		// 初始化为无穷远点（椭圆曲线群的单位元）
		let res = pointAtInfinity();
		let temp = new JacobianPoint(point.x, point.y, 1n);
		
		// 双重加法链算法（从最低有效位到最高有效位）
		for (let i = 0; i < bitLength; i++) {
			const byte = kBytes[kBytes.byteLength - 1 - Math.floor(i / 8)];
			// 如果当前位为1，则将temp加到结果
			if ((byte >> i % 8) & 0x01) {
				res = this.addJacobian(res, temp);
			}
			// 无论如何都将temp加倍
			temp = this.doubleJacobian(temp);
		}
		
		// 转回仿射坐标
		return this.toAffine(res);
	}

	/**
	 * 检查点是否在曲线上
	 * 
	 * 验证点是否满足椭圆曲线方程 y² = x³ + ax + b
	 * 对于余因子h>1的曲线，还需要检查点是否在主要子群中
	 * 
	 * @param point 要检查的点
	 * @returns 如果点在曲线上则返回true
	 */
	public isOnCurve(point: ECDSAPoint): boolean {
		// 对于余因子h>1，确保点在素数阶子群中
		if (this.cofactor !== 1n && this.multiply(this.n, point) !== null) {
			return false;
		}
		
		// 验证点是否满足曲线方程 y² = x³ + ax + b
		return (
			euclideanMod(point.y ** 2n, this.p) ===
			euclideanMod(point.x ** 3n + this.a * point.x + this.b, this.p)
		);
	}
}

/**
 * 创建无穷远点
 * 
 * 无穷远点是椭圆曲线群的单位元，在雅可比坐标中表示为(0:1:0)
 * 
 * @returns 雅可比坐标下的无穷远点
 */
function pointAtInfinity(): JacobianPoint {
	return new JacobianPoint(0n, 1n, 0n);
}
