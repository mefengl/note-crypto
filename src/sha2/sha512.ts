/**
 * SHA-512 哈希算法实现模块
 * 
 * SHA-512是SHA-2家族中最安全的哈希算法，生成512位（64字节）的哈希值。
 * 与SHA-256相比，SHA-512使用64位字而不是32位字进行计算，提供更强的安全性。
 * 
 * SHA-512的特点：
 * 1. 输出固定长度为512位的哈希值，比SHA-256提供更强的抗碰撞能力
 * 2. 使用64位操作，在64位处理器上可能比SHA-256更快
 * 3. 块大小为1024位（128字节），比SHA-256的512位（64字节）大一倍
 * 4. 常用于高安全性要求的场景，如数字签名、密钥派生等
 * 
 * SHA-512也是其他变体（SHA-384、SHA-512/224、SHA-512/256）的基础，
 * 这些变体使用不同的初始值和/或截断输出来实现不同的哈希长度。
 */

import { bigEndian } from "@oslojs/binary";
import { rotr64 } from "@oslojs/binary";
import type { Hash } from "../hash/index.js";

/**
 * SHA-512哈希函数 - 便捷版本
 * 
 * 这是一个方便的工具函数，适用于一次性处理较小数据。
 * 对于大型数据或需要流式处理的场景，建议直接使用SHA512类。
 * 
 * @example
 * // 计算字符串的SHA-512哈希值
 * const data = new TextEncoder().encode("Hello, world!");
 * const hash = sha512(data);
 * 
 * @param data 要计算哈希值的数据
 * @returns SHA-512哈希值（64字节/512位）
 */
export function sha512(data: Uint8Array): Uint8Array {
	const hash = new SHA512();
	hash.update(data);
	return hash.digest();
}

/**
 * SharedSHA512类 - SHA-512系列哈希算法的共享实现
 * 
 * 这个类提供了SHA-512系列所有变体的核心实现，
 * 通过传入不同的初始哈希值(H)来实现不同的变体（SHA-512、SHA-384等）。
 * 
 * 这种设计使代码更加模块化，避免了不同SHA-512变体之间的代码重复。
 */
export class SharedSHA512 {
	/**
	 * SHA-512的块大小为128字节（1024位）
	 */
	public blockSize = 128;
	
	/**
	 * SHA-512的基本输出大小为64字节（512位）
	 * 注意：具体变体的输出大小可能不同，如SHA-384输出48字节
	 */
	public size = 64;
	
	/**
	 * 当前处理块的缓冲区
	 * SHA-512算法每次处理128字节（1024位）的数据块
	 */
	private blocks = new Uint8Array(128);
	
	/**
	 * 当前已缓冲数据的大小（字节）
	 */
	private currentBlockSize = 0;
	
	/**
	 * 处理过的数据总长度（位）
	 * 使用BigInt类型以支持超长数据
	 */
	private l = 0n;
	
	/**
	 * 消息扩展用的80个64位字数组
	 * 在SHA-512的每轮处理中，原始的16个64位字会扩展成80个字
	 */
	private w = new BigUint64Array(80);
	
	/**
	 * SHA-512算法的8个64位哈希状态值（H0-H7）
	 * 不同的SHA-512变体使用不同的初始值
	 */
	private H: BigUint64Array;

	/**
	 * 构造函数 - 初始化SHA-512算法
	 * 
	 * @param H 初始哈希值数组，必须是8个64位值（共64字节）
	 * @throws TypeError 如果H不是64字节（8个64位值）
	 */
	constructor(H: BigUint64Array) {
		if (H.byteLength !== 64) {
			throw new TypeError();
		}
		this.H = H;
	}

	/**
	 * 更新哈希计算，添加更多数据
	 * 
	 * 支持分块处理大型数据，实现流式哈希计算。
	 * SHA-512使用更大的块大小（128字节），但处理逻辑与SHA-256类似。
	 * 
	 * @param data 要添加到哈希计算的数据
	 */
	public update(data: Uint8Array): void {
		// 更新已处理数据的总位长度
		this.l += BigInt(data.byteLength) * 8n;
		
		// 如果当前数据块未满，且新数据也填不满，直接添加到当前块
		if (this.currentBlockSize + data.byteLength < 128) {
			this.blocks.set(data, this.currentBlockSize);
			this.currentBlockSize += data.byteLength;
			return;
			}
		
		// 开始处理数据
		let processed = 0;
		
		// 如果当前块有部分数据，先填满并处理
		if (this.currentBlockSize > 0) {
			const next = data.slice(0, 128 - this.currentBlockSize);
			this.blocks.set(next, this.currentBlockSize);
			this.process(); // 处理完整的128字节块
			processed += next.byteLength;
			this.currentBlockSize = 0;
		}
		
		// 逐个处理完整的数据块（每块128字节）
		while (processed + 128 <= data.byteLength) {
			const next = data.slice(processed, processed + 128);
			this.blocks.set(next);
			this.process();
			processed += 128;
			this.currentBlockSize = 0;
			}
		
		// 保存剩余数据到下一块
		if (data.byteLength - processed > 0) {
			const remaining = data.slice(processed);
			this.blocks.set(remaining);
			this.currentBlockSize = remaining.byteLength;
		}
	}

	/**
	 * 将最终哈希值写入指定的结果缓冲区
	 * 
	 * 这个方法与常规digest方法的区别在于它允许接收不同大小的结果缓冲区，
	 * 从而支持SHA-512系列不同变体的输出大小（如SHA-384只取前48字节）。
	 * 
	 * @param result 接收哈希结果的缓冲区
	 * @throws TypeError 如果结果缓冲区大小大于64字节或不是8的倍数
	 */
	public putDigest(result: Uint8Array): void {
		// 验证结果缓冲区大小合法性
		if (result.byteLength > 64 || result.byteLength % 8 !== 0) {
			throw new TypeError();
		}
		
		// 添加填充的起始位：1后跟0（二进制中的10000000，即0x80）
		this.blocks[this.currentBlockSize] = 0x80;
		this.currentBlockSize += 1;
		
		// 如果剩余空间不足以存放消息长度（16字节），则填充0并处理当前块，再开始新块
		// SHA-512使用16字节（128位）来存储消息长度，而SHA-256只使用8字节（64位）
		if (128 - this.currentBlockSize < 16) {
			this.blocks.fill(0, this.currentBlockSize);
			this.process();
			this.currentBlockSize = 0;
		}
		
		// 填充0直到达到放置长度信息的位置
		this.blocks.fill(0, this.currentBlockSize);
		
		// 在最后16字节放置消息长度（以位为单位）
		// 但SHA-512目前只使用后8字节，前8字节为0，因为JavaScript的BigInt也无法表示如此之大的数值
		bigEndian.putUint64(this.blocks, this.l, this.blockSize - 8);
		
		// 处理最终块
		this.process();
		
		// 生成最终哈希值（将所需数量的64位值连接成输出）
		for (let i = 0; i < result.byteLength / 8; i++) {
			bigEndian.putUint64(result, this.H[i], i * 8);
		}
	}

	/**
	 * 处理单个完整的数据块（128字节/1024位）
	 * 
	 * SHA-512的核心处理功能，每个1024位块的处理步骤：
	 * 1. 将128字节数据分割为16个64位字（W[0]到W[15]）
	 * 2. 将这16个字扩展为80个字（W[0]到W[79]），使用特定的扩展规则
	 * 3. 初始化8个变量a,b,c,d,e,f,g,h为当前哈希值H0-H7
	 * 4. 主循环：执行80轮更新操作，每轮使用预计算的常量K[t]
	 * 5. 将计算结果添加到当前哈希值
	 */
	private process(): void {
		// 步骤1：准备消息块的前16个字（W[0]到W[15]）
		// 将每8个字节转换为一个64位字（大端序）
		for (let t = 0; t < 16; t++) {
			this.w[t] =
				(BigInt(this.blocks[t * 8]) << 56n) |
				(BigInt(this.blocks[t * 8 + 1]) << 48n) |
				(BigInt(this.blocks[t * 8 + 2]) << 40n) |
				(BigInt(this.blocks[t * 8 + 3]) << 32n) |
				(BigInt(this.blocks[t * 8 + 4]) << 24n) |
				(BigInt(this.blocks[t * 8 + 5]) << 16n) |
				(BigInt(this.blocks[t * 8 + 6]) << 8n) |
				BigInt(this.blocks[t * 8 + 7]);
		}
		
		// 步骤2：扩展16个字为80个字（W[16]到W[79]）
		for (let t = 16; t < 80; t++) {
			// σ1(W[t-2]) = ROTR^19(W[t-2]) ⊕ ROTR^61(W[t-2]) ⊕ SHR^6(W[t-2])
			// 注意这里与SHA-256使用不同的旋转和移位值
			const sigma1 =
				(rotr64(this.w[t - 2], 19) ^ rotr64(this.w[t - 2], 61) ^ (this.w[t - 2] >> 6n)) &
				0xffffffffffffffffn;
			
			// σ0(W[t-15]) = ROTR^1(W[t-15]) ⊕ ROTR^8(W[t-15]) ⊕ SHR^7(W[t-15])
			const sigma0 =
				(rotr64(this.w[t - 15], 1) ^ rotr64(this.w[t - 15], 8) ^ (this.w[t - 15] >> 7n)) &
				0xffffffffffffffffn;
			
			// W[t] = σ1(W[t-2]) + W[t-7] + σ0(W[t-15]) + W[t-16]
			this.w[t] = (sigma1 + this.w[t - 7] + sigma0 + this.w[t - 16]) & 0xffffffffffffffffn;
		}
		
		// 步骤3：初始化工作变量为当前哈希值
		let a = this.H[0];
		let b = this.H[1];
		let c = this.H[2];
		let d = this.H[3];
		let e = this.H[4];
		let f = this.H[5];
		let g = this.H[6];
		let h = this.H[7];
		
		// 步骤4：80轮主循环
		for (let t = 0; t < 80; t++) {
			// Σ1(e) = ROTR^14(e) ⊕ ROTR^18(e) ⊕ ROTR^41(e)
			// 注意这里与SHA-256使用不同的旋转值
			const sigma1 = (rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41)) & 0xffffffffffffffffn;
			
			// Ch(e,f,g) = (e AND f) ⊕ ((NOT e) AND g)
			const ch = ((e & f) ^ (~e & g)) & 0xffffffffffffffffn;
			
			// t1 = h + Σ1(e) + Ch(e,f,g) + K[t] + W[t]
			const t1 = (h + sigma1 + ch + K[t] + this.w[t]) & 0xffffffffffffffffn;
			
			// Σ0(a) = ROTR^28(a) ⊕ ROTR^34(a) ⊕ ROTR^39(a)
			const sigma0 = (rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39)) & 0xffffffffffffffffn;
			
			// Maj(a,b,c) = (a AND b) ⊕ (a AND c) ⊕ (b AND c)
			const maj = ((a & b) ^ (a & c) ^ (b & c)) & 0xffffffffffffffffn;
			
			// t2 = Σ0(a) + Maj(a,b,c)
			const t2 = (sigma0 + maj) & 0xffffffffffffffffn;

			// 更新工作变量
			h = g;            // h = g
			g = f;            // g = f
			f = e;            // f = e
			e = (d + t1) & 0xffffffffffffffffn; // e = d + t1
			d = c;            // d = c
			c = b;            // c = b
			b = a;            // b = a
			a = (t1 + t2) & 0xffffffffffffffffn; // a = t1 + t2
			
			// 每一步都使用掩码0xffffffffffffffffn（64位全1）确保结果是64位
		}
		
		// 步骤5：计算此块的新哈希值
		this.H[0] = (a + this.H[0]) & 0xffffffffffffffffn;
		this.H[1] = (b + this.H[1]) & 0xffffffffffffffffn;
		this.H[2] = (c + this.H[2]) & 0xffffffffffffffffn;
		this.H[3] = (d + this.H[3]) & 0xffffffffffffffffn;
		this.H[4] = (e + this.H[4]) & 0xffffffffffffffffn;
		this.H[5] = (f + this.H[5]) & 0xffffffffffffffffn;
		this.H[6] = (g + this.H[6]) & 0xffffffffffffffffn;
		this.H[7] = (h + this.H[7]) & 0xffffffffffffffffn;
	}
}

/**
 * SHA512类 - 实现标准SHA-512哈希算法
 * 
 * 这个类是SharedSHA512的包装器，使用标准SHA-512初始值，
 * 并实现了Hash接口，提供与其他哈希算法一致的API。
 */
export class SHA512 implements Hash {
	/**
	 * SHA-512的块大小为128字节（1024位）
	 */
	public blockSize = 128;
	
	/**
	 * SHA-512哈希输出大小为64字节（512位）
	 */
	public size = 64;
	
	/**
	 * 内部使用SharedSHA512实现核心功能
	 * 
	 * 初始哈希值是前8个素数（2,3,5,7,11,13,17,19）的平方根的小数部分的前64位
	 */
	private sha512 = new SharedSHA512(
		new BigUint64Array([
			0x6a09e667f3bcc908n, // sqrt(2)的小数部分
			0xbb67ae8584caa73bn, // sqrt(3)的小数部分
			0x3c6ef372fe94f82bn, // sqrt(5)的小数部分
			0xa54ff53a5f1d36f1n, // sqrt(7)的小数部分
			0x510e527fade682d1n, // sqrt(11)的小数部分
			0x9b05688c2b3e6c1fn, // sqrt(13)的小数部分
			0x1f83d9abfb41bd6bn, // sqrt(17)的小数部分
			0x5be0cd19137e2179n  // sqrt(19)的小数部分
		])
	);

	/**
	 * 更新哈希计算，添加更多数据
	 * 
	 * @param data 要添加到哈希计算的数据
	 */
	public update(data: Uint8Array): void {
		this.sha512.update(data);
	}

	/**
	 * 完成哈希计算并返回最终哈希值
	 * 
	 * @returns SHA-512哈希值（64字节Uint8Array）
	 */
	public digest(): Uint8Array {
		const result = new Uint8Array(64);
		this.sha512.putDigest(result);
		return result;
	}
}

/**
 * SHA-512算法中使用的80个常量
 * 
 * 这些常量是前80个素数（2,3,5,7,11,...）的立方根的小数部分的前64位
 * 常量的设计目的是为了消除算法中可能存在的数学对称性，增强安全性
 * 
 * 注意：SHA-512使用的是64位常量，而SHA-256使用32位常量
 */
const K = new BigUint64Array([
	0x428a2f98d728ae22n, 0x7137449123ef65cdn, 0xb5c0fbcfec4d3b2fn, 0xe9b5dba58189dbbcn,
	0x3956c25bf348b538n, 0x59f111f1b605d019n, 0x923f82a4af194f9bn, 0xab1c5ed5da6d8118n,
	0xd807aa98a3030242n, 0x12835b0145706fben, 0x243185be4ee4b28cn, 0x550c7dc3d5ffb4e2n,
	0x72be5d74f27b896fn, 0x80deb1fe3b1696b1n, 0x9bdc06a725c71235n, 0xc19bf174cf692694n,
	0xe49b69c19ef14ad2n, 0xefbe4786384f25e3n, 0x0fc19dc68b8cd5b5n, 0x240ca1cc77ac9c65n,
	0x2de92c6f592b0275n, 0x4a7484aa6ea6e483n, 0x5cb0a9dcbd41fbd4n, 0x76f988da831153b5n,
	0x983e5152ee66dfabn, 0xa831c66d2db43210n, 0xb00327c898fb213fn, 0xbf597fc7beef0ee4n,
	0xc6e00bf33da88fc2n, 0xd5a79147930aa725n, 0x06ca6351e003826fn, 0x142929670a0e6e70n,
	0x27b70a8546d22ffcn, 0x2e1b21385c26c926n, 0x4d2c6dfc5ac42aedn, 0x53380d139d95b3dfn,
	0x650a73548baf63den, 0x766a0abb3c77b2a8n, 0x81c2c92e47edaee6n, 0x92722c851482353bn,
	0xa2bfe8a14cf10364n, 0xa81a664bbc423001n, 0xc24b8b70d0f89791n, 0xc76c51a30654be30n,
	0xd192e819d6ef5218n, 0xd69906245565a910n, 0xf40e35855771202an, 0x106aa07032bbd1b8n,
	0x19a4c116b8d2d0c8n, 0x1e376c085141ab53n, 0x2748774cdf8eeb99n, 0x34b0bcb5e19b48a8n,
	0x391c0cb3c5c95a63n, 0x4ed8aa4ae3418acbn, 0x5b9cca4f7763e373n, 0x682e6ff3d6b2b8a3n,
	0x748f82ee5defb2fcn, 0x78a5636f43172f60n, 0x84c87814a1f0ab72n, 0x8cc702081a6439ecn,
	0x90befffa23631e28n, 0xa4506cebde82bde9n, 0xbef9a3f7b2c67915n, 0xc67178f2e372532bn,
	0xca273eceea26619cn, 0xd186b8c721c0c207n, 0xeada7dd6cde0eb1en, 0xf57d4f7fee6ed178n,
	0x06f067aa72176fban, 0x0a637dc5a2c898a6n, 0x113f9804bef90daen, 0x1b710b35131c471bn,
	0x28db77f523047d84n, 0x32caab7b40c72493n, 0x3c9ebe0a15c9bebcn, 0x431d67c49c100d4cn,
	0x4cc5d4becb3e42b6n, 0x597f299cfc657e2an, 0x5fcb6fab3ad6faecn, 0x6c44198c4a475817n
]);
