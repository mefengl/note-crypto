# Note Crypto

A cryptographic library for educational purposes, providing implementations of common cryptographic algorithms and protocols in TypeScript.

## Features

- Hash functions (SHA-1, SHA-2, SHA-3)
- HMAC (Hash-based Message Authentication Code)
- RSA (public key cryptography)
- ECDSA (Elliptic Curve Digital Signature Algorithm)
- Utilities for random number generation

## Installation

```bash
npm install note-crypto
```

## Usage

```typescript
// Example using SHA-256
import { SHA256 } from "note-crypto";

const hash = new SHA256();
hash.update(new TextEncoder().encode("Hello, world!"));
const digest = hash.digest();
console.log(Array.from(digest).map(b => b.toString(16).padStart(2, '0')).join(''));
```

## Security Notice

This library is primarily designed for educational purposes. While the implementations follow cryptographic standards, they have not undergone the rigorous security audits required for production-grade cryptographic libraries. For production use, please consider well-established libraries like OpenSSL, Libsodium, or Web Crypto API.

## Documentation

For detailed documentation and examples, see the [docs](./docs) directory.

---

# 中文阅读指南 (Chinese Reading Guide)

## 项目概述

Note Crypto 是一个用于教育目的的加密库，使用 TypeScript 实现了常见的密码学算法和协议。该库旨在帮助开发者和学生理解现代密码学的基本原理和实现细节。

## 推荐阅读顺序

为了更好地理解此加密库的代码，建议按照以下顺序阅读源代码：

### 1. 基础模块

1. **哈希函数接口** (`src/hash/index.ts`)
   - 理解哈希函数的基本接口和通用类型

2. **随机数生成工具** (`src/random/index.ts`)
   - 了解安全随机数生成的实现方式

### 2. 哈希算法实现

1. **SHA-1** (`src/sha1/index.ts`)
   - 经典哈希算法的实现（注意：SHA-1在现代应用中已不再安全）

2. **SHA-2系列**
   - SHA-2入口 (`src/sha2/index.ts`)
   - SHA-256实现 (`src/sha2/sha256.ts`)
   - SHA-512实现 (`src/sha2/sha512.ts`)
   - 其他SHA-2变体

3. **SHA-3系列**
   - SHA-3入口 (`src/sha3/index.ts`)
   - Keccak核心实现 (`src/sha3/sha3.ts`)
   - SHA-3哈希实现 (`src/sha3/hash.ts`)
   - SHAKE可扩展输出函数 (`src/sha3/xof.ts`)

### 3. 消息认证码

1. **HMAC实现** (`src/hmac/index.ts`)
   - 基于哈希函数的消息认证码

### 4. 对称加密

- AES实现 (`src/aes/index.ts`)
- ChaCha20实现 (`src/chacha20/index.ts`)

### 5. 公钥密码学

- X25519密钥交换 (`src/x25519/index.ts`)
- Ed25519数字签名 (`src/ed25519/index.ts`)
- RSA实现 (`src/rsa/index.ts`)
- ECDSA实现
- ECDSA入口 (`src/ecdsa/index.ts`)
- 椭圆曲线定义 (`src/ecdsa/curve.ts`)
- NIST标准曲线 (`src/ecdsa/curve-nist.ts`)
- SECG标准曲线 (`src/ecdsa/curve-sec.ts`)
- 签名生成与验证 (`src/ecdsa/ecdsa.ts`)
- 椭圆曲线数学运算 (`src/ecdsa/math.ts`)

## 核心概念说明

### 哈希函数

哈希函数将任意长度的输入数据映射为固定长度的输出（散列值）。良好的密码学哈希函数具有以下特性：

- **单向性**：从散列值计算原始数据在计算上不可行
- **抗碰撞性**：找到两个产生相同散列值的不同输入在计算上不可行
- **雪崩效应**：输入的微小变化导致输出的显著不同

SHA-1、SHA-2和SHA-3是三代不同的哈希算法标准。

### HMAC

HMAC（基于哈希的消息认证码）结合了密钥和哈希函数，用于验证消息的完整性和真实性。HMAC可以使用任何密码学哈希函数，如SHA-256或SHA-3。

### RSA

RSA是一种公钥密码系统，基于大整数质因数分解的困难性。RSA可用于加密、数字签名和密钥交换。本库实现了RSA的签名验证功能，包括PKCS#1 v1.5和PSS两种填充方案。

### ECDSA

ECDSA（椭圆曲线数字签名算法）是基于椭圆曲线密码学的数字签名方案。相比传统RSA，在相同安全级别下，ECDSA提供更小的密钥和签名长度、更快的签名生成和验证速度。

## 进一步探索

要深入理解实现细节，建议对照NIST标准文档阅读源代码中的详细注释。源代码中的每个文件都包含了全面的中文注释，解释了算法原理、实现细节和安全考虑。

---

## License

MIT
