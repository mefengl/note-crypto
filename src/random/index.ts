/**
 * 密码学安全随机数生成模块
 * 
 * 在密码学中，随机数的质量对安全性至关重要。这个模块提供了生成密码学安全随机数的工具函数。
 * 加密系统中的随机数必须具有不可预测性，否则可能导致密钥、盐值等安全参数被攻击者猜测，
 * 从而破坏整个加密系统的安全性。
 * 
 * 与普通随机数不同，密码学安全的随机数要求：
 * 1. 统计随机性 - 生成的数字序列通过各种统计随机性测试
 * 2. 不可预测性 - 攻击者无法预测下一个随机数
 * 3. 不可重现性 - 即使知道算法也无法重现相同的随机序列
 */

import { bigIntFromBytes } from "@oslojs/binary";

/**
 * 生成指定范围内的随机大整数
 * 
 * 这个函数在密码学中非常重要，例如在生成RSA密钥对时需要随机大素数，
 * 或在ECDSA签名算法中需要随机私钥等场景。
 * 
 * 函数使用拒绝采样法（rejection sampling）确保结果在正确范围内：
 * 1. 生成足够多的随机字节以覆盖max的位长度
 * 2. 将字节转换为大整数
 * 3. 如果大整数超出范围，重新生成直到得到范围内的值
 * 
 * @param random 随机数读取器，用于获取随机字节
 * @param max 随机数的上限（不包含）
 * @returns 返回一个在[0, max-1]范围内的随机大整数
 * @throws 如果max小于2或无法获取随机字节时，抛出错误
 */
export function generateRandomInteger(random: RandomReader, max: bigint): bigint {
	// 检查参数有效性
	if (max < 2) {
		throw new Error("Argument 'max' must be a positive integer larger than 1");
	}
	
	// 计算需要的位数和字节数
	const inclusiveMaxBitLength = (max - 1n).toString(2).length; // 转为二进制，计算位长度
	const shift = inclusiveMaxBitLength % 8; // 需要处理的不完整字节的位数
	const bytes = new Uint8Array(Math.ceil(inclusiveMaxBitLength / 8)); // 分配足够的字节
	
	// 读取随机字节
	try {
		random.read(bytes);
	} catch (e) {
		throw new Error("Failed to retrieve random bytes", {
			cause: e
		});
	}
	
	// 优化：处理不完整字节中的多余位
	// 这样可以增加生成的数在范围内的概率，减少重新生成的次数
	// 例如：如果max只需要10位表示，但我们读取了2个字节（16位），
	// 那么第一个字节的高6位可以被忽略（置为0），这样生成的数更可能小于max
	if (shift !== 0) {
		bytes[0] &= (1 << shift) - 1; // 将高位多余的位清零
	}
	
	// 将字节转换为大整数
	let result = bigIntFromBytes(bytes);
	
	// 如果生成的数大于等于max，则重新生成
	// 这就是拒绝采样法的核心思想
	while (result >= max) {
		try {
			random.read(bytes);
		} catch (e) {
			throw new Error("Failed to retrieve random bytes", {
				cause: e
			});
		}
		if (shift !== 0) {
			bytes[0] &= (1 << shift) - 1;
		}
		result = bigIntFromBytes(bytes);
	}
	
	return result;
}

/**
 * 生成指定范围内的随机JavaScript数字
 * 
 * 这是generateRandomInteger的包装函数，针对JavaScript数字类型做了优化。
 * 适用于需要较小范围随机数的场景，如生成随机索引、随机延迟时间等。
 * 
 * @param random 随机数读取器，用于获取随机字节
 * @param max 随机数的上限（不包含），必须是正整数且不超过安全整数范围
 * @returns 返回一个在[0, max-1]范围内的随机整数
 * @throws 如果max小于2或大于最大安全整数，抛出错误
 */
export function generateRandomIntegerNumber(random: RandomReader, max: number): number {
	if (max < 2 || max > Number.MAX_SAFE_INTEGER) {
		throw new Error("Argument 'max' must be a positive integer larger than 1");
	}
	return Number(generateRandomInteger(random, BigInt(max)));
}

/**
 * 生成指定字母表和长度的随机字符串
 * 
 * 这个函数常用于生成随机令牌、会话ID、临时密码等。
 * 通过指定不同的字母表，可以生成不同特性的随机字符串：
 * - 使用数字和字母可生成可读性好的随机ID
 * - 使用所有可打印字符可生成高熵值的随机密码
 * 
 * 示例：
 * - 生成随机密码：generateRandomString(random, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()", 12)
 * - 生成随机ID：generateRandomString(random, "ABCDEFGHJKLMNPQRSTUVWXYZ23456789", 8) // 避免容易混淆的字符如0,O,1,I
 * 
 * @param random 随机数读取器，用于获取随机字节
 * @param alphabet 字符串中可以使用的字符集
 * @param length 要生成的字符串长度
 * @returns 返回指定长度的随机字符串
 */
export function generateRandomString(
	random: RandomReader,
	alphabet: string,
	length: number
): string {
	let result = "";
	for (let i = 0; i < length; i++) {
		// 为每个位置从字母表中随机选择一个字符
		result += alphabet[generateRandomIntegerNumber(random, alphabet.length)];
	}
	return result;
}

/**
 * 随机数读取器接口
 * 
 * 这个接口定义了获取随机字节的标准方法。
 * 实现此接口的类负责提供密码学安全的随机数据。
 * 
 * 不同环境可以有不同的实现：
 * - 浏览器环境可以使用Web Crypto API (crypto.getRandomValues())
 * - Node.js环境可以使用crypto模块 (crypto.randomFillSync())
 * - 其他环境可以提供自己的实现
 * 
 * 这种设计允许库在不同运行环境中保持一致的API，同时利用环境特定的安全随机源。
 */
export interface RandomReader {
	/**
	 * 读取随机字节的方法
	 * 
	 * @param bytes 要填充随机值的Uint8Array缓冲区
	 * @throws 如果无法获取随机数据，应该抛出错误
	 */
	read(bytes: Uint8Array): void;
}
