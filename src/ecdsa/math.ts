/**
 * 椭圆曲线密码学 (ECC) 的基础模运算模块
 * 
 * 这个文件提供了一些在有限域（特别是素数域 GF(p)）上进行计算所必需的基础数学函数。
 * 这些函数是实现 ECDSA 签名、验证、密钥生成和处理等操作的核心构建块。
 */

/**
 * 计算欧几里得模 (Euclidean Modulo)
 * 
 * 这个函数计算 x 除以 y 的余数，并确保结果始终是非负的。
 * 这与 JavaScript 内建的 `%` 运算符不同，后者对于负数 x 可能会返回负数结果。
 * 在密码学计算中，我们通常需要一个落在 [0, y-1] 区间内的标准模结果。
 * 
 * 例如：euclideanMod(-1, 5) 返回 4, 而 (-1 % 5) 返回 -1.
 * 
 * @param x 被除数 (Dividend)
 * @param y 除数 (Divisor)，通常是有限域的模数 p 或群的阶 n
 * @returns x mod y 的非负结果
 */
export function euclideanMod(x: bigint, y: bigint): bigint {
	const r = x % y;
	// 如果 JavaScript 的 % 运算符返回了负数，通过加上模数 y 将其调整到 [0, y-1] 范围
	if (r < 0n) {
		return r + y;
	}
	return r;
}

/**
 * 计算模乘法逆元 (Modular Multiplicative Inverse)
 * 
 * 这个函数计算整数 a 在模 n 下的乘法逆元。也就是说，找到一个整数 s，使得 (a * s) mod n = 1。
 * 模逆元只在 a 和 n 互质（它们的最大公约数为 1）时存在。
 * 这个函数使用了扩展欧几里得算法 (Extended Euclidean Algorithm) 来找到这个逆元。
 * 
 * 模逆元在密码学中非常重要，例如：
 * - 在 ECDSA 签名验证中，需要计算 s (签名的一部分) 的模逆元 w = s⁻¹ mod n。
 * - 在进行椭圆曲线点加法运算时，计算斜率也需要模逆元。
 * 
 * @param a 需要求逆元的整数
 * @param n 模数 (Modulus)，通常是有限域的模数 p 或群的阶 n
 * @returns a 在模 n 下的乘法逆元 s
 * @throws 如果 a 和 n 不互质（即逆元不存在），则抛出错误
 */
export function inverseMod(a: bigint, n: bigint): bigint {
	// 确保模数 n 为正数
	if (n < 0) {
		n = n * -1n;
	}
	// 确保 a 在 [0, n-1] 范围内
	if (a < 0) {
		a = euclideanMod(a, n);
	}

	// 扩展欧几里得算法初始化
	let dividend = a;      // 被除数，初始为 a
	let divisor = n;       // 除数，初始为 n
	let remainder = dividend % divisor; // 余数
	let quotient = dividend / divisor;  // 商
	let s1 = 1n;           // 贝祖等式系数 s 的前一项 (对应 a)
	let s2 = 0n;           // 贝祖等式系数 s 的当前项 (对应 n)
	let s3 = s1 - quotient * s2; // 贝祖等式系数 s 的下一项

	// 迭代执行欧几里得除法，并更新贝祖等式系数
	while (remainder !== 0n) {
		dividend = divisor;
		divisor = remainder;
		s1 = s2;
		s2 = s3;
		remainder = dividend % divisor;
		quotient = dividend / divisor;
		s3 = s1 - quotient * s2;
	}

	// 循环结束时，divisor 是 a 和 n 的最大公约数 (GCD)
	// 如果 GCD 不为 1，说明 a 和 n 不互质，逆元不存在
	if (divisor !== 1n) {
		throw new Error("a and n is not relatively prime");
	}

	// s2 此时就是 a 的模 n 逆元。如果 s2 是负数，加上 n 使其变为正数。
	if (s2 < 0) {
		return s2 + n;
	}
	return s2;
}

/**
 * 计算模幂 (Modular Exponentiation)
 * 
 * 这个函数计算 x 的 y 次方在模 p 下的结果，即 (x^y) mod p。
 * 它使用了称为“平方-乘算法”（或二进制幂算法、快速幂）的高效方法，
 * 避免了直接计算巨大的中间值 x^y。
 * 算法复杂度大约是 O(log y)，远快于朴素的 O(y) 乘法。
 * 
 * 模幂运算是许多公钥密码算法（如 RSA、Diffie-Hellman、ECDSA 中的点乘）的基础。
 * 
 * @param x 底数 (Base)
 * @param y 指数 (Exponent)
 * @param p 模数 (Modulus)
 * @returns (x^y) mod p 的结果
 */
export function powmod(x: bigint, y: bigint, p: bigint): bigint {
	let res = 1n; // 初始化结果为 1
	x = x % p; // 预先对底数取模，减少计算量
	while (y > 0) {
		// 如果指数 y 的当前最低位是 1 (即 y 是奇数)
		if (y % 2n === 1n) {
			// 将当前 x 的幂次乘入结果
			res = euclideanMod(res * x, p);
		}
		// 将指数 y 右移一位 (相当于除以 2)
		y = y >> 1n;
		// 将底数 x 平方并取模，为下一轮做准备
		x = euclideanMod(x * x, p);
	}
	return res;
}

/**
 * Tonelli-Shanks 算法：计算模平方根
 * 
 * 这个函数计算 n 在模 p 下的平方根，即找到一个整数 r 使得 (r*r) mod p = n。
 * 这里假设 p 是一个奇素数。
 * 
 * 算法步骤：
 * 1. 处理特殊情况：如果 p ≡ 3 (mod 4)，有一个简单的公式可以直接计算平方根。
 * 2. 检查 n 是否是模 p 的二次剩余（即平方根是否存在）。如果 n^((p-1)/2) ≡ -1 (mod p)，则无解。
 * 3. 将 p-1 分解为 q * 2^s，其中 q 是奇数。
 * 4. 找到一个模 p 的二次非剩余 z。
 * 5. 初始化 R, T, C, M。
 * 6. 进入主循环，不断调整 R, T, C, M，直到找到平方根或确定无解。
 * 
 * 这个算法在椭圆曲线密码学中用于：
 * - 从压缩格式的公钥恢复 Y 坐标：已知 X 坐标，需要通过曲线方程 y² = x³ + ax + b (mod p)
 *   计算 y² 的值，然后使用 Tonelli-Shanks 找到 y。
 * 
 * @param n 需要开平方的数 (必须是模 p 的二次剩余)
 * @param p 模数 (必须是奇素数)
 * @returns n 模 p 的一个平方根 r (注意：通常存在两个平方根 r 和 -r mod p)
 * @throws 如果 n 不是模 p 的二次剩余（即无平方根），则抛出错误
 */
// assumes p is prime
// https://en.wikipedia.org/wiki/Tonelli–Shanks_algorithm#The_algorithm
export function tonelliShanks(n: bigint, p: bigint): bigint {
	// 特殊情况: 如果 p ≡ 3 (mod 4)，计算平方根有简单公式
	if (p % 4n === 3n) {
		// r = n^((p+1)/4) mod p
		return powmod(n, (p + 1n) / 4n, p);
	}

	// 检查 n 是否是二次剩余 (Euler's criterion)
	// 如果 n^((p-1)/2) ≡ -1 (mod p)，则 n 不是二次剩余，无解
	if (powmod(n, (p - 1n) / 2n, p) === p - 1n) {
		throw new Error("Cannot find square root");
	}

	// 步骤 3: 分解 p-1 = q * 2^s
	let q = p - 1n;
	let s = 0n;
	while (q % 2n === 0n) {
		q = q / 2n;
		s++;
	}

	// 步骤 4: 找到一个二次非剩余 z
	let z = 2n;
	while (powmod(z, (p - 1n) / 2n, p) !== p - 1n) {
		z++;
	}

	// 步骤 5: 初始化
	let r = powmod(n, (q + 1n) / 2n, p); // R = n^((Q+1)/2) mod p
	let t = powmod(n, q, p);           // t = n^Q mod p
	let c = powmod(z, q, p);           // c = z^Q mod p
	let m = s;                         // M = S

	// 步骤 6: 主循环
	// eslint-disable-next-line no-constant-condition
	while (true) {
		// 如果 t 等于 1，则当前的 r 就是平方根
		if (t === 1n) {
			return r;
		}
		// 找到最小的 i > 0 使得 t^(2^i) ≡ 1 (mod p)
		let i = 1n;
		while (i <= m) {
			if (i === m) {
				// 如果循环到 m 还没有找到，说明算法有问题或输入有误
				throw new Error("Cannot find square root");
			}
			if (powmod(t, 2n ** i, p) === 1n) {
				break;
			}
			i++;
		}
		// 计算 b = c^(2^(M-i-1)) mod p
		const b = powmod(c, 2n ** (m - i - 1n), p);
		// 更新 M, c, t, R
		m = i;
		c = powmod(b, 2n, p); // c = b^2 mod p
		t = euclideanMod(t * powmod(b, 2n, p), p); // t = t * b^2 mod p
		r = euclideanMod(r * b, p); // r = r * b mod p
	}
}
