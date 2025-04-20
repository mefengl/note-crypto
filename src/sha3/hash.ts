/**
 * SHA-3 哈希算法实现模块
 * 
 * SHA-3（Secure Hash Algorithm 3）是最新的密码哈希函数标准，由Keccak算法家族设计。
 * 与SHA-1和SHA-2不同，SHA-3基于海绵结构（sponge construction）设计，提供了更好的安全性和性能特性。
 * 
 * SHA-3的特点：
 * 1. 基于海绵构造，使用置换函数而非压缩函数
 * 2. 具有更强的抗量子计算攻击能力
 * 3. 提供灵活的输出长度（224位、256位、384位、512位）
 * 4. 支持可扩展输出函数（XOF）如SHAKE128和SHAKE256
 * 5. 内部状态大（1600位），增强了安全性
 * 
 * 本模块实现了SHA3-224、SHA3-256、SHA3-384和SHA3-512四种变体。
 */

import { SHA3 } from "./sha3.js";
import type { Hash } from "../hash/index.js";

/**
 * SHA3-224哈希函数 - 便捷版本
 * 
 * 计算数据的SHA3-224哈希值，输出28字节（224位）的摘要。
 * 这是一个方便的工具函数，适用于一次性处理较小数据。
 * 
 * @example
 * // 计算字符串的SHA3-224哈希值
 * const data = new TextEncoder().encode("Hello, world!");
 * const hash = sha3_224(data);
 * // 结果是28字节的Uint8Array
 * 
 * @param data 要计算哈希值的数据
 * @returns SHA3-224哈希值（28字节/224位）
 */
export function sha3_224(data: Uint8Array): Uint8Array {
	const hash = new SHA3_224();
	hash.update(data);
	return hash.digest();
}

/**
 * SHA3-256哈希函数 - 便捷版本
 * 
 * 计算数据的SHA3-256哈希值，输出32字节（256位）的摘要。
 * 这是SHA-3系列中最常用的变体，提供与SHA-256相同长度但不同结构的哈希值。
 * 
 * @param data 要计算哈希值的数据
 * @returns SHA3-256哈希值（32字节/256位）
 */
export function sha3_256(data: Uint8Array): Uint8Array {
	const hash = new SHA3_256();
	hash.update(data);
	return hash.digest();
}

/**
 * SHA3-384哈希函数 - 便捷版本
 * 
 * 计算数据的SHA3-384哈希值，输出48字节（384位）的摘要。
 * 
 * @param data 要计算哈希值的数据
 * @returns SHA3-384哈希值（48字节/384位）
 */
export function sha3_384(data: Uint8Array): Uint8Array {
	const hash = new SHA3_384();
	hash.update(data);
	return hash.digest();
}

/**
 * SHA3-512哈希函数 - 便捷版本
 * 
 * 计算数据的SHA3-512哈希值，输出64字节（512位）的摘要。
 * 这是SHA-3系列中提供最高安全强度的变体。
 * 
 * @param data 要计算哈希值的数据
 * @returns SHA3-512哈希值（64字节/512位）
 */
export function sha3_512(data: Uint8Array): Uint8Array {
	const hash = new SHA3_512();
	hash.update(data);
	return hash.digest();
}

/**
 * SHA3-224类 - 实现SHA3-224哈希算法
 * 
 * SHA3-224提供224位的输出，是SHA-3系列中安全强度较低的变体。
 * 适用于对空间有限制但仍需要足够安全性的场景。
 * 
 * 注意：SHA3-224的内部状态是1600位，但其速率（rate）是1600-2×224=1152位（144字节）
 */
export class SHA3_224 implements Hash {
	/**
	 * SHA3-224的块大小为144字节（1152位）
	 * 这是海绵构造中的"速率"（rate）参数r
	 */
	public blockSize = 144;
	
	/**
	 * SHA3-224哈希输出大小为28字节（224位）
	 */
	public size = 28;
	
	/**
	 * 内部SHA-3实例，处理核心Keccak算法
	 */
	private sha3 = new SHA3(this.blockSize, this.size);
	
	/**
	 * 更新哈希计算，添加更多数据
	 * 
	 * 在SHA-3的海绵模型中，这一步被称为"吸收"（absorb）阶段
	 * 
	 * @param data 要添加到哈希计算的数据
	 */
	public update(data: Uint8Array): void {
		this.sha3.absorb(data);
	}
	
	/**
	 * 完成哈希计算并返回最终哈希值
	 * 
	 * 在SHA-3的海绵模型中，这一步被称为"挤出"（squeeze）阶段
	 * 
	 * @returns SHA3-224哈希值（28字节Uint8Array）
	 */
	public digest(): Uint8Array {
		return this.sha3.squeeze();
	}
}

/**
 * SHA3-256类 - 实现SHA3-256哈希算法
 * 
 * SHA3-256提供256位的输出，是SHA-3系列中最常用的变体。
 * 提供与SHA-256相当的安全强度，但基于完全不同的数学结构。
 * 
 * 注意：SHA3-256的内部状态是1600位，但其速率是1600-2×256=1088位（136字节）
 */
export class SHA3_256 implements Hash {
	/**
	 * SHA3-256的块大小为136字节（1088位）
	 */
	public blockSize = 136;
	
	/**
	 * SHA3-256哈希输出大小为32字节（256位）
	 */
	public size = 32;
	
	/**
	 * 内部SHA-3实例，处理核心Keccak算法
	 */
	private sha3 = new SHA3(this.blockSize, this.size);
	
	/**
	 * 更新哈希计算，添加更多数据（吸收阶段）
	 */
	public update(data: Uint8Array): void {
		this.sha3.absorb(data);
	}
	
	/**
	 * 完成哈希计算并返回最终哈希值（挤出阶段）
	 */
	public digest(): Uint8Array {
		return this.sha3.squeeze();
	}
}

/**
 * SHA3-384类 - 实现SHA3-384哈希算法
 * 
 * SHA3-384提供384位的输出，适用于需要更高安全强度的场景。
 * 常用于安全性要求较高的数字签名和证书系统。
 * 
 * 注意：SHA3-384的内部状态是1600位，但其速率是1600-2×384=832位（104字节）
 */
export class SHA3_384 implements Hash {
	/**
	 * SHA3-384的块大小为104字节（832位）
	 */
	public blockSize = 104;
	
	/**
	 * SHA3-384哈希输出大小为48字节（384位）
	 */
	public size = 48;
	
	/**
	 * 内部SHA-3实例，处理核心Keccak算法
	 */
	private sha3 = new SHA3(this.blockSize, this.size);
	
	/**
	 * 更新哈希计算，添加更多数据（吸收阶段）
	 */
	public update(data: Uint8Array): void {
		this.sha3.absorb(data);
	}
	
	/**
	 * 完成哈希计算并返回最终哈希值（挤出阶段）
	 */
	public digest(): Uint8Array {
		return this.sha3.squeeze();
	}
}

/**
 * SHA3-512类 - 实现SHA3-512哈希算法
 * 
 * SHA3-512提供512位的输出，是SHA-3系列中提供最高安全强度的变体。
 * 适用于对安全性要求极高的应用场景。
 * 
 * 注意：SHA3-512的内部状态是1600位，但其速率是1600-2×512=576位（72字节）
 */
export class SHA3_512 implements Hash {
	/**
	 * SHA3-512的块大小为72字节（576位）
	 */
	public blockSize = 72;
	
	/**
	 * SHA3-512哈希输出大小为64字节（512位）
	 */
	public size = 64;
	
	/**
	 * 内部SHA-3实例，处理核心Keccak算法
	 */
	private sha3 = new SHA3(this.blockSize, this.size);
	
	/**
	 * 更新哈希计算，添加更多数据（吸收阶段）
	 */
	public update(data: Uint8Array): void {
		this.sha3.absorb(data);
	}
	
	/**
	 * 完成哈希计算并返回最终哈希值（挤出阶段）
	 */
	public digest(): Uint8Array {
		return this.sha3.squeeze();
	}
}
