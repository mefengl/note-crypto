/**
 * SHA-3 可扩展输出函数 (XOF - Extendable-Output Function) 实现模块
 * 
 * XOF 是一种特殊的哈希函数，它可以根据需要产生任意长度的输出，
 * 这与传统的哈希函数（如 SHA-256）输出固定长度的摘要不同。
 * 想象一下，它就像一个神奇的海绵，吸入了任意多的水（输入数据），
 * 然后你可以拧出任意长度的水流（输出哈希值）。
 * 
 * SHAKE (Secure Hash Algorithm KEccak) 是基于 Keccak 算法（SHA-3 的基础）的 XOF 标准。
 * 主要有两个变体：SHAKE128 和 SHAKE256，它们的区别在于内部的安全强度级别。
 * 
 * XOF 的主要用途：
 * 1. 密钥派生函数 (KDF): 从一个密码或共享秘密生成多个密钥。
 * 2. 生成伪随机数: 产生看起来随机的数据流。
 * 3. 可变长度的消息认证码。
 * 
 * 本模块基于 `./sha3.js` 中的 `SHA3XOF` 类，实现了 SHAKE128 和 SHAKE256。
 * 它提供了两种使用方式：
 * - 便捷函数 (`shake128`, `shake256`)：用于一次性计算少量数据的 XOF 输出。
 * - 类 (`SHAKE128`, `SHAKE256`)：用于处理大数据流，可以分块 `update`。
 */

import { SHA3XOF } from "./sha3.js";
import type { Hash } from "../hash/index.js";

/**
 * SHAKE128 哈希函数 - 便捷版本
 * 
 * 计算数据的 SHAKE128 哈希值，并返回指定长度的输出。
 * SHAKE128 提供大约 128 位的安全强度。
 * 
 * 就像用一个小海绵快速吸水然后拧出指定量的水。
 * 
 * @example
 * // 计算字符串 "Hello" 的 SHAKE128 哈希，输出 32 字节
 * const data = new TextEncoder().encode("Hello");
 * const outputSizeInBytes = 32;
 * const hash = shake128(outputSizeInBytes, data);
 * // hash 是一个 32 字节的 Uint8Array
 * 
 * @param size 需要生成的哈希值的字节长度 (可以任意指定)
 * @param data 要计算哈希值的数据
 * @returns 指定长度的 SHAKE128 哈希值
 */
export function shake128(size: number, data: Uint8Array): Uint8Array {
	// 创建一个 SHAKE128 实例，指定输出大小
	const hash = new SHAKE128(size);
	// 将所有数据一次性喂给它（吸收）
	hash.update(data);
	// 完成计算并获取结果（挤压）
	return hash.digest();
}

/**
 * SHAKE256 哈希函数 - 便捷版本
 * 
 * 计算数据的 SHAKE256 哈希值，并返回指定长度的输出。
 * SHAKE256 提供大约 256 位的安全强度，比 SHAKE128 更强。
 * 
 * 就像用一个安全级别更高的大海绵快速吸水然后拧出指定量的水。
 * 
 * @example
 * // 计算字符串 "World" 的 SHAKE256 哈希，输出 64 字节
 * const data = new TextEncoder().encode("World");
 * const outputSizeInBytes = 64;
 * const hash = shake256(outputSizeInBytes, data);
 * // hash 是一个 64 字节的 Uint8Array
 * 
 * @param size 需要生成的哈希值的字节长度 (可以任意指定)
 * @param data 要计算哈希值的数据
 * @returns 指定长度的 SHAKE256 哈希值
 */
export function shake256(size: number, data: Uint8Array): Uint8Array {
	// 创建一个 SHAKE256 实例，指定输出大小
	const hash = new SHAKE256(size);
	// 将所有数据一次性喂给它（吸收）
	hash.update(data);
	// 完成计算并获取结果（挤压）
	return hash.digest();
}

/**
 * SHAKE128 类 - 实现 SHAKE128 可扩展输出函数
 * 
 * 这个类提供了流式处理接口，可以分多次调用 `update` 方法来添加数据，
 * 最后调用 `digest` 方法获取指定长度的哈希输出。
 * 
 * 它内部使用了 `./sha3.js` 中定义的 `SHA3XOF` 类，并配置了 SHAKE128 特定的参数。
 * 实现了通用的 `Hash` 接口，以便与其他哈希算法保持一致性。
 */
export class SHAKE128 implements Hash {
	/**
	 * SHAKE128 的块大小（吸收速率 Rate）为 168 字节 (1344 位)。
	 * 这是 Keccak 海绵结构中每轮可以"吸收"的数据量。
	 * 计算方式: (1600 - 2 * 128) / 8 = 1344 / 8 = 168 字节。
	 * 1600 是 Keccak 内部状态的总位数。
	 * 2 * 128 是容量 (Capacity)，用于保证安全强度，不直接参与数据吸收。
	 */
	public blockSize = 168;
	
	/**
	 * 期望输出的哈希值的字节长度。
	 * 这个值在创建实例时由用户指定。
	 */
	public size: number;

	/**
	 * 内部持有的 SHA3XOF 实例。
	 * 它负责执行实际的 Keccak 吸收和挤压操作。
	 */
	private sha3: SHA3XOF;

	/**
	 * 创建一个 SHAKE128 哈希实例。
	 * 
	 * @param size 期望输出的哈希值的字节长度。
	 *             必须大于 0。
	 */
	constructor(size: number) {
		// 检查输出大小是否有效
		if (size < 1) {
			throw new TypeError("Invalid hash size"); // 无效的哈希大小
		}
		this.size = size;
		// 初始化内部的 SHA3XOF 实例，传入 SHAKE128 的块大小和期望的输出大小
		this.sha3 = new SHA3XOF(this.blockSize, this.size);
	}

	/**
	 * 更新哈希计算，添加更多数据。
	 * 这是海绵结构的"吸收"（Absorb）阶段。
	 * 你可以多次调用这个方法来处理大数据流。
	 * 
	 * @param data 要添加到哈希计算的数据块
	 */
	public update(data: Uint8Array): void {
		// 调用内部 SHA3XOF 实例的 absorb 方法来处理数据
		this.sha3.absorb(data);
	}

	/**
	 * 完成哈希计算并返回最终的、指定长度的哈希值。
	 * 这是海绵结构的"挤压"（Squeeze）阶段。
	 * 一旦调用此方法，就不能再调用 `update` 了。
	 * 
	 * @returns 指定长度的 SHAKE128 哈希值 (Uint8Array)
	 */
	public digest(): Uint8Array {
		// 调用内部 SHA3XOF 实例的 squeeze 方法来获取最终结果
		return this.sha3.squeeze();
	}
}

/**
 * SHAKE256 类 - 实现 SHAKE256 可扩展输出函数
 * 
 * 这个类提供了流式处理接口，用于计算 SHAKE256 哈希。
 * SHAKE256 提供约 256 位的安全强度，比 SHAKE128 更安全。
 * 
 * 同样内部使用了 `SHA3XOF` 类，但配置了 SHAKE256 特定的参数。
 * 实现了通用的 `Hash` 接口。
 */
export class SHAKE256 implements Hash {
	/**
	 * SHAKE256 的块大小（吸收速率 Rate）为 136 字节 (1088 位)。
	 * 计算方式: (1600 - 2 * 256) / 8 = 1088 / 8 = 136 字节。
	 * 容量 (Capacity) 更大 (2 * 256 = 512 位)，因此速率较低，但安全性更高。
	 */
	public blockSize = 136;
	
	/**
	 * 期望输出的哈希值的字节长度。
	 */
	public size: number;

	/**
	 * 内部持有的 SHA3XOF 实例。
	 */
	private sha3: SHA3XOF;

	/**
	 * 创建一个 SHAKE256 哈希实例。
	 * 
	 * @param size 期望输出的哈希值的字节长度。
	 *             必须大于 0。
	 */
	constructor(size: number) {
		// 检查输出大小是否有效 (虽然 XOF 可以输出任意长度，但通常我们期望至少 1 字节)
		if (size < 1) {
			throw new TypeError("Invalid hash size"); // 无效的哈希大小
		}
		this.size = size;
		// 初始化内部的 SHA3XOF 实例，传入 SHAKE256 的块大小和期望的输出大小
		this.sha3 = new SHA3XOF(this.blockSize, this.size);
	}

	/**
	 * 更新哈希计算，添加更多数据（吸收阶段）。
	 * 
	 * @param data 要添加到哈希计算的数据块
	 */
	public update(data: Uint8Array): void {
		this.sha3.absorb(data);
	}

	/**
	 * 完成哈希计算并返回最终的、指定长度的哈希值（挤压阶段）。
	 * 
	 * @returns 指定长度的 SHAKE256 哈希值 (Uint8Array)
	 */
	public digest(): Uint8Array {
		return this.sha3.squeeze();
	}
}
