/**
 * SHA-1 哈希算法实现模块
 * 
 * SHA-1（Secure Hash Algorithm 1）是一种密码散列函数，生成160位（20字节）哈希值。
 * 
 * 虽然SHA-1已被证明不够安全（可能受到碰撞攻击），不推荐用于新的安全应用，
 * 但由于历史原因，它仍然在许多系统中被使用。现代应用应当考虑使用SHA-2或SHA-3系列算法。
 * 
 * SHA-1工作原理：
 * 1. 对输入消息进行填充，使其长度是512位的倍数
 * 2. 初始化5个32位哈希值（H0-H4）
 * 3. 将消息分成512位（64字节）的块并处理
 * 4. 每个块通过80轮的哈希计算更新哈希值
 * 5. 输出最终的160位哈希值
 */

import { bigEndian } from "@oslojs/binary";
import { rotl32 } from "@oslojs/binary";
import type { Hash } from "../hash/index.js";

/**
 * SHA-1哈希函数 - 便捷版本
 * 
 * 这是一个方便的工具函数，对于小型数据（小于2000字节）计算效率较高。
 * 对于大型数据或需要流式处理的场景，建议直接使用SHA1类。
 * 
 * 注意：对于小于2000字节的数据，这个实现可能比Web Crypto API更快或相当。
 * 
 * @param data 要计算哈希值的数据
 * @returns SHA-1哈希值（20字节/160位）
 */
export function sha1(data: Uint8Array): Uint8Array {
	const hash = new SHA1();
	hash.update(data);
	return hash.digest();
}

/**
 * SHA1类 - 实现SHA-1哈希算法
 * 
 * 这个类实现了Hash接口，提供完整的SHA-1哈希功能，
 * 支持流式处理大型数据，可以多次调用update方法添加数据。
 */
export class SHA1 implements Hash {
	/**
	 * SHA-1的块大小为64字节（512位）
	 * 这是算法处理数据的基本单位
	 */
	public blockSize = 64;
	
	/**
	 * SHA-1哈希输出大小为20字节（160位）
	 */
	public size = 20;
	
	/**
	 * 当前处理块的缓冲区
	 * SHA-1算法每次处理64字节（512位）的数据块
	 */
	private blocks = new Uint8Array(64);
	
	/**
	 * 当前已缓冲数据的大小（字节）
	 */
	private currentBlockSize = 0;
	
	/**
	 * SHA-1算法的5个32位哈希状态值（H0-H4）
	 * 这些初始值由算法规范定义，计算过程中不断更新，
	 * 最终组成160位的哈希结果
	 */
	private H = new Uint32Array([0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]);
	
	/**
	 * 处理过的数据总长度（位）
	 */
	private l = 0;
	
	/**
	 * 消息扩展用的80个32位字数组
	 * 在SHA-1的每轮处理中，原始的16个32位字会扩展成80个字
	 */
	private w = new Uint32Array(80);

	/**
	 * 更新哈希计算，添加更多数据
	 * 
	 * 支持分块处理大型数据，实现流式哈希计算。
	 * 处理逻辑：
	 * 1. 更新数据总长度计数器
	 * 2. 如果当前块未满，先填充当前块
	 * 3. 如果当前块已满，处理当前块
	 * 4. 处理完整的数据块
	 * 5. 保存剩余数据到下一个块
	 * 
	 * @param data 要添加到哈希计算的数据
	 */
	public update(data: Uint8Array): void {
		// 更新已处理数据的总位长度
		this.l += data.byteLength * 8;
		
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
	 * SHA-1算法的填充规则：
	 * 1. 添加一个1位，然后是一些0位，使得最终长度对512取模等于448
	 * 2. 末尾添加64位的原始消息长度（位）
	 * 
	 * 在代码中：
	 * - 添加的1位表示为0x80（二进制10000000）
	 * - 余下的填充用0实现
	 * - 最后8字节（64位）存放消息长度
	 * 
	 * @returns SHA-1哈希值（20字节Uint8Array）
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
		bigEndian.putUint64(this.blocks, BigInt(this.l), this.blockSize - 8);
		
		// 处理最终块
		this.process();
		
		// 生成最终哈希值（将5个32位值连接成20字节输出）
		const result = new Uint8Array(20);
		for (let i = 0; i < 5; i++) {
			bigEndian.putUint32(result, this.H[i], i * 4);
		}
		
		return result;
	}

	/**
	 * 处理单个完整的数据块（64字节/512位）
	 * 
	 * SHA-1的核心处理功能，每个512位块的处理步骤：
	 * 1. 将64字节数据分割为16个32位字（W[0]到W[15]）
	 * 2. 将这16个字扩展为80个字（W[0]到W[79]）
	 * 3. 初始化5个变量a, b, c, d, e为当前哈希值H0-H4
	 * 4. 主循环：执行80轮更新操作
	 * 5. 将计算结果添加到当前哈希值
	 * 
	 * SHA-1的四个轮次使用不同的逻辑函数和常量：
	 * - 轮次1（0-19）：Ch(x,y,z) = (x AND y) XOR ((NOT x) AND z)，K = 0x5a827999
	 * - 轮次2（20-39）：Parity(x,y,z) = x XOR y XOR z，K = 0x6ed9eba1
	 * - 轮次3（40-59）：Maj(x,y,z) = (x AND y) XOR (x AND z) XOR (y AND z)，K = 0x8f1bbcdc
	 * - 轮次4（60-79）：Parity(x,y,z) = x XOR y XOR z，K = 0xca62c1d6
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
		
		// 步骤2：扩展16个字为80个字（W[16]到W[79]）
		for (let t = 16; t < 80; t++) {
			// 计算方式: W[t] = ROTL1(W[t-3] XOR W[t-8] XOR W[t-14] XOR W[t-16])
			// >>> 0 确保结果是无符号32位整数
			this.w[t] = rotl32(
				(this.w[t - 3] ^ this.w[t - 8] ^ this.w[t - 14] ^ this.w[t - 16]) >>> 0,
				1
			);
		}
		
		// 步骤3：初始化工作变量
		let a = this.H[0];
		let b = this.H[1];
		let c = this.H[2];
		let d = this.H[3];
		let e = this.H[4];
		
		// 步骤4：80轮主循环
		for (let t = 0; t < 80; t++) {
			let F, K: number;
			
			// 根据轮次选择不同的逻辑函数和常量
			if (t < 20) {
				// Ch(b,c,d) = (b AND c) XOR ((NOT b) AND d)
				F = ((b & c) ^ (~b & d)) >>> 0;
				K = 0x5a827999; // sqrt(2) * 2^30
			} else if (t < 40) {
				// Parity(b,c,d) = b XOR c XOR d
				F = (b ^ c ^ d) >>> 0;
				K = 0x6ed9eba1; // sqrt(3) * 2^30
			} else if (t < 60) {
				// Maj(b,c,d) = (b AND c) XOR (b AND d) XOR (c AND d)
				F = ((b & c) ^ (b & d) ^ (c & d)) >>> 0;
				K = 0x8f1bbcdc; // sqrt(5) * 2^30
			} else {
				// Parity(b,c,d) = b XOR c XOR d
				F = (b ^ c ^ d) >>> 0;
				K = 0xca62c1d6; // sqrt(10) * 2^30
			}
			
			// T = ROTL5(a) + F(b,c,d) + e + K + W[t]
			const T = (rotl32(a, 5) + e + F + this.w[t] + K) | 0;
			
			// 更新工作变量
			e = d;          // e = d
			d = c;          // d = c
			c = rotl32(b, 30); // c = ROTL30(b)
			b = a;          // b = a
			a = T;          // a = T
		}
		
		// 步骤5：计算此块的新哈希值
		// | 0 确保结果是有符号32位整数
		this.H[0] = (this.H[0] + a) | 0;
		this.H[1] = (this.H[1] + b) | 0;
		this.H[2] = (this.H[2] + c) | 0;
		this.H[3] = (this.H[3] + d) | 0;
		this.H[4] = (this.H[4] + e) | 0;
	}
}
