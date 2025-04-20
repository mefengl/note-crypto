/**
 * SHA-3/Keccak 核心算法实现模块
 * 
 * SHA-3是基于Keccak算法的哈希函数标准，采用"海绵结构"（sponge construction）设计。
 * 海绵结构包含两个阶段：
 * 1. 吸收阶段（Absorb）：将输入数据块逐步吸收到状态中
 * 2. 挤压阶段（Squeeze）：从状态中提取哈希值
 * 
 * SHA-3的内部状态是一个5×5×64=1600位的三维数组，算法使用一系列置换函数（θ、ρ、π、χ、ι）
 * 对这个状态进行变换，这些函数共同构成了Keccak-f[1600]置换。
 */

import { rotl64 } from "@oslojs/binary";

/**
 * SHA3类 - 实现基本的SHA-3哈希函数
 * 
 * 此类实现了SHA-3的海绵结构，用于生成固定长度的哈希值（如SHA3-224、SHA3-256等）。
 * SHA-3算法使用不同的填充和领域分隔值（domain separation value）与SHAKE区分。
 */
export class SHA3 {
	/**
	 * 吸收率（比特/轮）- 每轮可以处理的数据位数
	 * 不同的SHA-3变体有不同的吸收率：
	 * - SHA3-224: 1152位（144字节）
	 * - SHA3-256: 1088位（136字节）
	 * - SHA3-384: 832位（104字节）
	 * - SHA3-512: 576位（72字节）
	 */
	private rate: number;
	
	/**
	 * 输出大小（字节）- 最终哈希值的字节长度
	 * - SHA3-224: 28字节
	 * - SHA3-256: 32字节
	 * - SHA3-384: 48字节
	 * - SHA3-512: 64字节
	 */
	private outputSize: number;
	
	/**
	 * Keccak状态 - 1600位（25个64位字）
	 * 这是SHA-3算法的核心，可以看作5×5的64位字矩阵
	 */
	private state = new BigUint64Array(25);
	
	/**
	 * 已吸收的字节数 - 跟踪当前状态已吸收的数据量
	 * 当达到吸收率时，会触发Keccak-f置换并重置
	 */
	private absorbedBytes = 0;

	/**
	 * 构造SHA3哈希实例
	 * 
	 * @param rate 吸收率（字节）- 每次可以吸收的数据量
	 * @param outputSize 输出大小（字节）- 哈希值的长度
	 */
	constructor(rate: number, outputSize: number) {
		this.rate = rate;
		this.outputSize = outputSize;
	}

	/**
	 * 吸收阶段 - 将数据吸收到状态中
	 * 
	 * 吸收过程：
	 * 1. 逐字节将输入数据与状态进行异或
	 * 2. 当吸收的数据量达到率值时，执行Keccak-f置换
	 * 3. 重置计数器，继续吸收剩余数据
	 * 
	 * @param bytes 要吸收的数据
	 */
	public absorb(bytes: Uint8Array): void {
		for (let i = 0; i < bytes.byteLength; i++) {
			// 将每个字节异或到状态的对应位置
			// Math.floor(this.absorbedBytes / 8)计算当前字节应该放入的64位字索引
			// (BigInt(this.absorbedBytes % 8) * 8n)计算在64位字内的位偏移
			this.state[Math.floor(this.absorbedBytes / 8)] ^=
				BigInt(bytes[i]) << (BigInt(this.absorbedBytes % 8) * 8n);
			
			// 更新已吸收的字节计数
			this.absorbedBytes++;
			
			// 如果达到吸收率，执行Keccak-f置换并重置计数器
			if (this.absorbedBytes === this.rate) {
				keccak(this.state);
				this.absorbedBytes = 0;
			}
		}
	}

	/**
	 * 挤压阶段 - 从状态中提取哈希值
	 * 
	 * 挤压过程：
	 * 1. 添加填充和领域分隔值（0x06）
	 * 2. 添加帧位（0x80）到最后一个字节
	 * 3. 执行Keccak-f置换
	 * 4. 从状态中提取所需长度的输出
	 * 
	 * @returns 最终的哈希值
	 */
	public squeeze(): Uint8Array {
		// 添加SHA-3的领域分隔值0x06（区别于SHAKE的0x1F）
		this.state[Math.floor(this.absorbedBytes / 8)] ^=
			0x06n << (BigInt(this.absorbedBytes % 8) * 8n);
		
		// 添加帧位（设置状态最高位为1）
		this.state[Math.floor((this.rate - 1) / 8)] ^= 0x8000000000000000n;
		
		// 执行最终的Keccak-f置换
		keccak(this.state);
		
		// 如果输出大小小于或等于吸收率，直接从状态中提取结果
		if (this.outputSize <= this.rate) {
			return new Uint8Array(this.state.buffer).slice(0, this.outputSize);
		}
		
		// 如果需要更多输出，多次执行Keccak-f置换
		const keccakCount = Math.ceil(this.outputSize / this.rate);
		const z = new Uint8Array(keccakCount * this.rate);
		
		// 提取第一部分输出
		z.set(new Uint8Array(this.state.buffer).slice(0, this.rate));
		
		// 继续执行Keccak-f置换并提取更多输出
		for (let i = 1; i < keccakCount; i++) {
			keccak(this.state);
			z.set(new Uint8Array(this.state.buffer).slice(0, this.rate), i * this.rate);
			}
		
		// 截取所需长度的输出
		return z.slice(0, this.outputSize);
	}
}

/**
 * SHA3XOF类 - 实现SHA-3的可扩展输出函数（SHAKE）
 * 
 * XOF（Extendable Output Function）允许生成任意长度的输出。
 * SHAKE变体（SHAKE128和SHAKE256）使用不同的领域分隔值（0x1F）与标准SHA-3区分。
 */
export class SHA3XOF {
	/**
	 * 吸收率（字节）- 每轮可以处理的数据量
	 * - SHAKE128: 1344位（168字节）
	 * - SHAKE256: 1088位（136字节）
	 */
	private rate: number;
	
	/**
	 * 输出大小（字节）- 最终哈希值的字节长度
	 * 对于SHAKE，这可以是任意长度
	 */
	private outputSize: number;
	
	/**
	 * Keccak状态 - 与SHA3类相同
	 */
	private state = new BigUint64Array(25);
	
	/**
	 * 已吸收的字节数 - 与SHA3类相同
	 */
	private absorbedBytes = 0;

	/**
	 * 构造SHA3XOF哈希实例
	 * 
	 * @param rate 吸收率（字节）
	 * @param outputSize 输出大小（字节）
	 */
	constructor(rate: number, outputSize: number) {
		this.rate = rate;
		this.outputSize = outputSize;
	}

	/**
	 * 吸收阶段 - 与SHA3类的实现相同
	 * 
	 * @param bytes 要吸收的数据
	 */
	public absorb(bytes: Uint8Array): void {
		for (let i = 0; i < bytes.byteLength; i++) {
			this.state[Math.floor(this.absorbedBytes / 8)] ^=
				BigInt(bytes[i]) << (BigInt(this.absorbedBytes % 8) * 8n);
			this.absorbedBytes++;
			if (this.absorbedBytes === this.rate) {
				keccak(this.state);
				this.absorbedBytes = 0;
			}
		}
	}

	/**
	 * 挤压阶段 - 与SHA3类似，但使用不同的领域分隔值
	 * 
	 * @returns 可变长度的哈希值
	 */
	public squeeze(): Uint8Array {
		// 添加SHAKE的领域分隔值0x1F（区别于SHA-3的0x06）
		this.state[Math.floor(this.absorbedBytes / 8)] ^=
			0x1fn << (BigInt(this.absorbedBytes % 8) * 8n);
		
		// 添加帧位（与SHA3相同）
		this.state[Math.floor((this.rate - 1) / 8)] ^= 0x8000000000000000n;
		
		// 后续挤压过程与SHA3相同
		keccak(this.state);
		if (this.outputSize <= this.rate) {
			return new Uint8Array(this.state.buffer).slice(0, this.outputSize);
		}
		const keccakCount = Math.ceil(this.outputSize / this.rate);
		const z = new Uint8Array(keccakCount * this.rate);
		z.set(new Uint8Array(this.state.buffer).slice(0, this.rate));
		for (let i = 1; i < keccakCount; i++) {
			keccak(this.state);
			z.set(new Uint8Array(this.state.buffer).slice(0, this.rate), i * this.rate);
		}
		return z.slice(0, this.outputSize);
	}
}

/**
 * Keccak-f[1600]置换函数
 * 
 * 这是SHA-3的核心运算，对1600位状态执行24轮变换，
 * 每轮包含5个步骤：θ(theta)、ρ(rho)、π(pi)、χ(chi)和ι(iota)
 * 
 * @param a Keccak状态（25个64位字）
 */
function keccak(a: BigUint64Array): void {
	// 执行24轮Keccak-f置换
	for (let i = 0; i < 24; i++) {
		theta(a); // θ步骤：列奇偶校验混合
		rho(a);   // ρ步骤：位旋转
		pi(a);    // π步骤：位置置换
		chi(a);   // χ步骤：非线性变换
		iota(a, i); // ι步骤：添加轮常量
	}
}

/**
 * θ(theta)变换 - 列奇偶校验混合
 * 
 * θ步骤通过混合每列的奇偶性来扩散每个位的影响。
 * 它执行以下操作：
 * 1. 计算每列的奇偶校验和（C数组）
 * 2. 计算每列的扩散值（D数组）
 * 3. 将扩散值应用到状态的每一位
 * 
 * @param a Keccak状态
 */
function theta(a: BigUint64Array): void {
	// 计算每列的奇偶校验和
	const c = new BigUint64Array(5);
	for (let x = 0; x < 5; x++) {
		c[x] = a[x];
		c[x] ^= a[x + 5];   // 与第二行异或
		c[x] ^= a[x + 10];  // 与第三行异或
		c[x] ^= a[x + 15];  // 与第四行异或
		c[x] ^= a[x + 20];  // 与第五行异或
	}
	
	// 计算扩散值
	const d = new BigUint64Array(5);
	for (let x = 0; x < 5; x++) {
		// d[x] = c[(x+4)%5] ^ rotl(c[(x+1)%5], 1)
		// 将前一列循环左移1位后与后一列异或
		d[x] = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
	}
	
	// 将扩散值应用到状态中的每一位
	for (let x = 0; x < 5; x++) {
		for (let y = 0; y < 5; y++) {
			a[x + y * 5] ^= d[x];
		}
	}
}

/**
 * ρ(rho)变换 - 位旋转
 * 
 * ρ步骤对状态中的每个字执行特定的位旋转，
 * 不同位置的字使用不同的旋转值。
 * 这一步增加状态的扩散性。
 * 
 * @param a Keccak状态
 */
function rho(a: BigUint64Array): void {
	// 位置(0,0)保持不变，其余位置按照预定义模式旋转
	// shifts数组包含每个位置的旋转位数
	const shifts = [
		0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14
	];
	
	// 对每个位置应用位旋转
	for (let i = 0; i < 25; i++) {
		a[i] = rotl64(a[i], shifts[i]);
	}
}

/**
 * π(pi)变换 - 位置置换
 * 
 * π步骤重新排列状态中字的位置，
 * 这种重新排列模式有助于实现比特的长期扩散。
 * 
 * @param a Keccak状态
 */
function pi(a: BigUint64Array): void {
	// dests数组定义了元素的置换目标位置
	const dests = [
		0, 10, 20, 5, 15, 16, 1, 11, 21, 6, 7, 17, 2, 12, 22, 23, 8, 18, 3, 13, 14, 24, 9, 19, 4
	];
	
	// 创建临时数组存储原始状态
	const temp = new BigUint64Array(a);
	
	// 执行位置置换
	for (let i = 0; i < 25; i++) {
		a[dests[i]] = temp[i];
	}
}

/**
 * χ(chi)变换 - 非线性变换
 * 
 * χ步骤是SHA-3中唯一的非线性操作，
 * 它独立地对状态中的每一行执行非线性变换。
 * 此变换对于SHA-3的加密安全性至关重要。
 * 
 * @param a Keccak状态
 */
function chi(a: BigUint64Array): void {
	// 创建临时数组存储原始状态
	const temp = new BigUint64Array(a);
	
	// 对每一行执行非线性变换：a[x,y] ^= ~a[x+1,y] & a[x+2,y]
	for (let x = 0; x < 5; x++) {
		for (let y = 0; y < 5; y++) {
			a[x + 5 * y] ^= ~temp[((x + 1) % 5) + 5 * y] & temp[((x + 2) % 5) + 5 * y];
		}
	}
}

/**
 * ι(iota)变换 - 添加轮常量
 * 
 * ι步骤通过加入轮常量打破对称性，
 * 它仅修改状态的第一个字(0,0)，
 * 每一轮使用不同的常量。
 * 
 * @param a Keccak状态
 * @param i 当前轮索引（0-23）
 */
function iota(a: BigUint64Array, i: number): void {
	// 将轮常量与第一个字异或
	a[0] ^= iotaConstants[i];
}

/**
 * Keccak-f[1600]中使用的24个轮常量
 * 
 * 这些常量是根据特定的数学规则生成的，
 * 用于破坏算法中的对称性，增强安全性。
 */
const iotaConstants = new BigUint64Array([
	0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
	0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
	0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
	0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
	0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
	0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n
]);
