/**
 * SHA-256 哈希算法实现模块
 * 
 * SHA-256是SHA-2家族中最常用的哈希算法，生成256位（32字节）的哈希值。
 * 它被广泛应用于数字签名、区块链（如比特币）、SSL证书、数据完整性校验等场景。
 * 
 * SHA-256的特点：
 * 1. 输出固定长度为256位的哈希值，无论输入数据多大
 * 2. 单向性强，无法从哈希值反推原始数据
 * 3. 雪崩效应显著，输入的微小变化导致输出的巨大差异
 * 4. 抗碰撞性强，很难找到两个不同的输入产生相同的哈希值
 * 
 * SHA-256处理过程：
 * 1. 将消息填充到512位的倍数
 * 2. 将消息分成512位的块
 * 3. 初始化8个32位哈希值（H0-H7）
 * 4. 对每个块执行64轮压缩函数
 * 5. 输出最终的256位哈希值
 */

import { bigEndian } from "@oslojs/binary";
import { rotr32 } from "@oslojs/binary";
import type { Hash } from "../hash/index.js";

/**
 * SHA-256哈希函数 - 便捷版本
 * 
 * 这是一个方便的工具函数，适用于一次性处理较小数据。
 * 对于大型数据或需要流式处理的场景，建议直接使用SHA256类。
 * 
 * @example
 * // 计算字符串的SHA-256哈希值
 * const data = new TextEncoder().encode("Hello, world!");
 * const hash = sha256(data);
 * // 结果是32字节的Uint8Array，可以转换为十六进制字符串
 * const hexHash = Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join('');
 * 
 * @param data 要计算哈希值的数据
 * @returns SHA-256哈希值（32字节/256位）
 */
export function sha256(data: Uint8Array): Uint8Array {
	const hash = new SHA256();
	hash.update(data);
	return hash.digest();
}

/**
 * SHA256类 - 实现SHA-256哈希算法
 * 
 * 这个类实现了Hash接口，提供完整的SHA-256哈希功能，
 * 支持流式处理大型数据，可以多次调用update方法添加数据。
 */
export class SHA256 implements Hash {
	/**
	 * SHA-256的块大小为64字节（512位）
	 * 这是算法处理数据的基本单位
	 */
	public blockSize = 64;
	
	/**
	 * SHA-256哈希输出大小为32字节（256位）
	 */
	public size = 32;
	
	/**
	 * 当前处理块的缓冲区
	 * SHA-256算法每次处理64字节（512位）的数据块
	 */
	private blocks = new Uint8Array(64);
	
	/**
	 * 当前已缓冲数据的大小（字节）
	 */
	private currentBlockSize = 0;
	
	/**
	 * SHA-256算法的8个32位哈希状态值（H0-H7）
	 * 这些初始值由算法规范定义，是前8个素数（2,3,5,7,11,13,17,19）的平方根小数部分的前32位
	 */
	private H = new Uint32Array([
		0x6a09e667, // sqrt(2)的小数部分
		0xbb67ae85, // sqrt(3)的小数部分
		0x3c6ef372, // sqrt(5)的小数部分
		0xa54ff53a, // sqrt(7)的小数部分
		0x510e527f, // sqrt(11)的小数部分
		0x9b05688c, // sqrt(13)的小数部分
		0x1f83d9ab, // sqrt(17)的小数部分
		0x5be0cd19  // sqrt(19)的小数部分
	]);
	
	/**
	 * 处理过的数据总长度（位）
	 * 使用BigInt类型以支持超过2^53位长度的消息
	 */
	private l = 0n;
	
	/**
	 * 消息扩展用的64个32位字数组
	 * 在SHA-256的每轮处理中，原始的16个32位字会扩展成64个字
	 */
	private w = new Uint32Array(64);

	/**
	 * 更新哈希计算，添加更多数据
	 * 
	 * 支持分块处理大型数据，实现流式哈希计算。
	 * 处理逻辑与SHA-1类似，但有以下区别：
	 * 1. SHA-256使用BigInt跟踪消息长度，支持处理超长数据
	 * 2. 内部状态和计算过程针对SHA-256算法优化
	 * 
	 * @param data 要添加到哈希计算的数据
	 */
	public update(data: Uint8Array): void {
		// 更新已处理数据的总位长度（使用BigInt以支持超大数据）
		this.l += BigInt(data.byteLength) * 8n;
		
		// 如果当前数据块未满，且新数据也填不满，直接添加到当前块
		if (this.currentBlockSize + data.byteLength < 64) {
			this.blocks.set(data, this.currentBlockSize);
			this.currentBlockSize += data.byteLength;
			return;
			}
		
		// 开始处理数据
		let processed = 0;
		
		// 如果当前块有部分数据，先填满并处理
		if (this.currentBlockSize > 0) {
			const next = data.slice(0, 64 - this.currentBlockSize);
			this.blocks.set(next, this.currentBlockSize);
			this.process(); // 处理完整的64字节块
			processed += next.byteLength;
			this.currentBlockSize = 0;
		}
		
		// 逐个处理完整的数据块（每块64字节）
		while (processed + 64 <= data.byteLength) {
			const next = data.slice(processed, processed + 64);
			this.blocks.set(next);
			this.process();
			processed += 64;
			}
		
		// 保存剩余数据到下一块
		if (data.byteLength - processed > 0) {
			const remaining = data.slice(processed);
			this.blocks.set(remaining);
			this.currentBlockSize = remaining.byteLength;
		}
	}

	/**
	 * 完成哈希计算并返回最终哈希值
	 * 
	 * SHA-256算法的填充规则与SHA-1类似：
	 * 1. 添加一个1位，然后是一些0位，使得最终长度对512取模等于448
	 * 2. 末尾添加64位的原始消息长度（位）
	 * 
	 * @returns SHA-256哈希值（32字节Uint8Array）
	 */
	public digest(): Uint8Array {
		// 添加填充的起始位：1后跟0（二进制中的10000000，即0x80）
		this.blocks[this.currentBlockSize] = 0x80;
		this.currentBlockSize += 1;
		
		// 如果剩余空间不足以存放消息长度（8字节），则填充0并处理当前块，再开始新块
		if (64 - this.currentBlockSize < 8) {
			this.blocks.fill(0, this.currentBlockSize);
			this.process();
			this.currentBlockSize = 0;
		}
		
		// 填充0直到达到放置长度信息的位置
		this.blocks.fill(0, this.currentBlockSize);
		
		// 在最后8字节放置消息长度（以位为单位）
		bigEndian.putUint64(this.blocks, this.l, this.blockSize - 8);
		
		// 处理最终块
		this.process();
		
		// 生成最终哈希值（将8个32位值连接成32字节输出）
		const result = new Uint8Array(32);
		for (let i = 0; i < 8; i++) {
			bigEndian.putUint32(result, this.H[i], i * 4);
		}
		
		return result;
	}

	/**
	 * 处理单个完整的数据块（64字节/512位）
	 * 
	 * SHA-256的核心处理功能，每个512位块的处理步骤：
	 * 1. 将64字节数据分割为16个32位字（W[0]到W[15]）
	 * 2. 将这16个字扩展为64个字（W[0]到W[63]），使用特定的扩展规则
	 * 3. 初始化8个变量a,b,c,d,e,f,g,h为当前哈希值H0-H7
	 * 4. 主循环：执行64轮更新操作，每轮使用预计算的常量K[t]
	 * 5. 将计算结果添加到当前哈希值
	 */
	private process(): void {
		// 步骤1：准备消息块的前16个字（W[0]到W[15]）
		// 将每4个字节转换为一个32位字（大端序）
		for (let t = 0; t < 16; t++) {
			this.w[t] =
				((this.blocks[t * 4] << 24) |
					(this.blocks[t * 4 + 1] << 16) |
					(this.blocks[t * 4 + 2] << 8) |
					this.blocks[t * 4 + 3]) >>>
				0;
		}
		
		// 步骤2：扩展16个字为64个字（W[16]到W[63]）
		for (let t = 16; t < 64; t++) {
			// σ1(W[t-2]) = ROTR^17(W[t-2]) ⊕ ROTR^19(W[t-2]) ⊕ SHR^10(W[t-2])
			const sigma1 =
				(rotr32(this.w[t - 2], 17) ^ rotr32(this.w[t - 2], 19) ^ (this.w[t - 2] >>> 10)) >>> 0;
			
			// σ0(W[t-15]) = ROTR^7(W[t-15]) ⊕ ROTR^18(W[t-15]) ⊕ SHR^3(W[t-15])
			const sigma0 =
				(rotr32(this.w[t - 15], 7) ^ rotr32(this.w[t - 15], 18) ^ (this.w[t - 15] >>> 3)) >>> 0;
			
			// W[t] = σ1(W[t-2]) + W[t-7] + σ0(W[t-15]) + W[t-16]
			this.w[t] = (sigma1 + this.w[t - 7] + sigma0 + this.w[t - 16]) | 0;
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
		
		// 步骤4：64轮主循环
		for (let t = 0; t < 64; t++) {
			// Σ1(e) = ROTR^6(e) ⊕ ROTR^11(e) ⊕ ROTR^25(e)
			const sigma1 = (rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)) >>> 0;
			
			// Ch(e,f,g) = (e AND f) ⊕ ((NOT e) AND g)
			const ch = ((e & f) ^ (~e & g)) >>> 0;
			
			// t1 = h + Σ1(e) + Ch(e,f,g) + K[t] + W[t]
			const t1 = (h + sigma1 + ch + K[t] + this.w[t]) | 0;
			
			// Σ0(a) = ROTR^2(a) ⊕ ROTR^13(a) ⊕ ROTR^22(a)
			const sigma0 = (rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)) >>> 0;
			
			// Maj(a,b,c) = (a AND b) ⊕ (a AND c) ⊕ (b AND c)
			const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
			
			// t2 = Σ0(a) + Maj(a,b,c)
			const t2 = (sigma0 + maj) | 0;

			// 更新工作变量
			h = g;            // h = g
			g = f;            // g = f
			f = e;            // f = e
			e = (d + t1) | 0; // e = d + t1
			d = c;            // d = c
			c = b;            // c = b
			b = a;            // b = a
			a = (t1 + t2) | 0; // a = t1 + t2
		}
		
		// 步骤5：计算此块的新哈希值
		// | 0 确保结果是有符号32位整数
		this.H[0] = (a + this.H[0]) | 0;
		this.H[1] = (b + this.H[1]) | 0;
		this.H[2] = (c + this.H[2]) | 0;
		this.H[3] = (d + this.H[3]) | 0;
		this.H[4] = (e + this.H[4]) | 0;
		this.H[5] = (f + this.H[5]) | 0;
		this.H[6] = (g + this.H[6]) | 0;
		this.H[7] = (h + this.H[7]) | 0;
	}
}

/**
 * SHA-256算法中使用的64个常量
 * 
 * 这些常量是前64个素数（2,3,5,7,11,...）的立方根的小数部分的前32位
 * 常量的设计目的是为了消除算法中可能存在的数学对称性，增强安全性
 */
const K = new Uint32Array([
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);
