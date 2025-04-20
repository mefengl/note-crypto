/**
 * HMAC (基于哈希的消息认证码) 实现模块
 * 
 * HMAC是一种使用加密哈希函数和密钥来同时验证数据完整性和真实性的技术。
 * 它可以与任何迭代哈希函数（如SHA-1、SHA-256、SHA-3等）配合使用。
 * 
 * HMAC的主要特点：
 * 1. 结合了密钥和哈希函数，提供了比单纯哈希更强的安全性
 * 2. 可以防止长度扩展攻击（这是普通哈希函数的一个弱点）
 * 3. 广泛应用于API认证、数据完整性校验、会话令牌等场景
 * 4. 安全性主要依赖于所使用的哈希函数和密钥的保密性
 * 
 * HMAC的计算公式：
 * HMAC(K,m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))
 * 其中：
 * - K是密钥
 * - K'是从K派生的固定大小密钥（如果K太长则哈希，如果太短则填充）
 * - m是消息
 * - H是哈希函数
 * - opad是外部填充（0x5c重复）
 * - ipad是内部填充（0x36重复）
 * - ⊕ 表示异或操作
 * - || 表示连接操作
 */
import { bigEndian } from "@oslojs/binary";
import type { Hash, HashAlgorithm } from "../hash/index.js";

/**
 * HMAC函数 - 便捷版本
 * 
 * 使用指定的哈希算法和密钥计算消息的HMAC值。
 * 这是一个方便的工具函数，适用于一次性计算HMAC。
 * 
 * @example
 * // 计算字符串的HMAC-SHA256
 * import { SHA256 } from "note-crypto";
 * const key = new TextEncoder().encode("secret-key");
 * const data = new TextEncoder().encode("Hello, world!");
 * const mac = hmac(SHA256, key, data);
 * 
 * @param Hash 用于HMAC的哈希算法构造函数
 * @param key HMAC密钥
 * @param data 要计算HMAC的消息数据
 * @returns HMAC值（长度与哈希函数输出长度相同）
 */
export function hmac(Hash: HashAlgorithm, key: Uint8Array, data: Uint8Array): Uint8Array {
	const hmacObj = new HMAC(Hash, key);
	hmacObj.update(data);
	return hmacObj.digest();
}

/**
 * HMAC类 - 实现基于哈希函数的消息认证码
 * 
 * 这个类提供了可重用的HMAC计算接口，支持流式处理数据，
 * 适用于需要分块计算HMAC的场景。
 */
export class HMAC implements Hash {
	/**
	 * 内部哈希函数实例
	 * 用于计算最终的HMAC值
	 */
	private hash: Hash;
	
	/**
	 * 内部状态：是否已经调用过update方法
	 * 用于确保在首次update时正确初始化
	 */
	private initialized = false;
	
	/**
	 * 内部缓存的经过ipad处理的密钥哈希实例
	 * 在update方法中使用
	 */
	private innerHash: Hash;
	
	/**
	 * 外部填充处理过的密钥
	 * 将在最终digest时与innerHash的结果组合
	 */
	private outerKey: Uint8Array;

	/**
	 * 构造HMAC对象
	 * 
	 * 初始化过程：
	 * 1. 如果密钥长度大于哈希块大小，则先对密钥进行哈希处理
	 * 2. 如果密钥长度小于哈希块大小，则用0填充到块大小
	 * 3. 准备内部和外部密钥：K ⊕ ipad 和 K ⊕ opad
	 * 4. 使用内部密钥初始化innerHash
	 * 5. 保存外部密钥以供后续使用
	 * 
	 * @param Hash 哈希算法构造函数（如SHA-256）
	 * @param key HMAC密钥
	 */
	constructor(Hash: HashAlgorithm, key: Uint8Array) {
		// 创建一个新的哈希实例，用于可能的密钥处理和最终HMAC计算
		this.hash = new Hash();
		
		// 创建内部哈希实例，用于处理(K ⊕ ipad) || m部分
		this.innerHash = new Hash();
		
		// 获取块大小（对于处理密钥很重要）
		const blockSize = this.innerHash.blockSize;
		
		// 准备处理过的密钥K'
		let processedKey: Uint8Array;
		
		// 如果密钥长度大于块大小，则对密钥进行哈希
		if (key.byteLength > blockSize) {
			const tempHash = new Hash();
			tempHash.update(key);
			processedKey = tempHash.digest();
		} else {
			// 否则直接使用原始密钥
			processedKey = key;
		}
		
		// 创建内部密钥和外部密钥缓冲区（块大小长度）
		const innerKey = new Uint8Array(blockSize);
		this.outerKey = new Uint8Array(blockSize);
		
		// 如果密钥短于块大小，其余部分已经是0（Uint8Array默认用0填充）
		innerKey.set(processedKey);
		this.outerKey.set(processedKey);
		
		// 应用内部填充（K' ⊕ ipad，其中ipad是0x36重复）
		for (let i = 0; i < blockSize; i++) {
			innerKey[i] ^= 0x36;
		}
		
		// 应用外部填充（K' ⊕ opad，其中opad是0x5c重复）
		for (let i = 0; i < blockSize; i++) {
			this.outerKey[i] ^= 0x5c;
		}
		
		// 开始内部哈希计算，处理内部密钥
		this.innerHash.update(innerKey);
	}

	/**
	 * HMAC的块大小，与内部使用的哈希函数相同
	 */
	public get blockSize(): number {
		return this.hash.blockSize;
	}

	/**
	 * HMAC的输出大小，与内部使用的哈希函数相同
	 */
	public get size(): number {
		return this.hash.size;
	}

	/**
	 * 更新HMAC计算，添加更多数据
	 * 
	 * 在HMAC中，这一步处理的是"(K' ⊕ ipad) || m"中的"m"部分
	 * 
	 * @param data 要添加到HMAC计算的数据块
	 */
	public update(data: Uint8Array): void {
		// 标记已初始化
		this.initialized = true;
		
		// 更新内部哈希计算，添加消息数据
		this.innerHash.update(data);
	}

	/**
	 * 完成HMAC计算并返回最终结果
	 * 
	 * 计算过程：
	 * 1. 完成内部哈希计算：H((K' ⊕ ipad) || m)
	 * 2. 初始化最终哈希计算，处理外部密钥：(K' ⊕ opad)
	 * 3. 将内部哈希结果添加到最终哈希：H((K' ⊕ opad) || H((K' ⊕ ipad) || m))
	 * 
	 * @returns HMAC值（长度与哈希函数输出长度相同）
	 */
	public digest(): Uint8Array {
		// 确保至少执行了一次update
		if (!this.initialized) {
			this.update(new Uint8Array(0));
		}
		
		// 获取内部哈希结果
		const innerHash = this.innerHash.digest();
		
		// 重新初始化哈希对象，先处理外部密钥
		this.hash.update(this.outerKey);
		
		// 然后添加内部哈希结果
		this.hash.update(innerHash);
		
		// 返回最终HMAC结果
		return this.hash.digest();
	}
}
