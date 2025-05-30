---
title: "ECDSAPublicKey"
---

# ECDSAPublicKey

Represents an ECDSA public key. It does not validate if the point is on the curve.

## Definition

```ts
//$ ECDSANamedCurve=/reference/ecdsa/ECDSANamedCurve
function constructor(curve: $$ECDSANamedCurve, x: bigint, y: bigint): this;
```

### Parameters

- `curve`
- `x`
- `y`

## Methods

- [`encodeSEC1Compressed()`](/reference/ecdsa/ECDSAPublicKey/encodeSEC1Compressed)
- [`encodeSEC1Uncompressed()`](/reference/ecdsa/ECDSAPublicKey/encodeSEC1Uncompressed)
- [`encodePKIXCompressed()`](/reference/ecdsa/ECDSAPublicKey/encodePKIXCompressed)
- [`encodePKIXUncompressed()`](/reference/ecdsa/ECDSAPublicKey/encodePKIXUncompressed)
- [`isCurve()`](/referecen/main/ECDSAPublicKey/isCurve)

## Properties

```ts
interface Properties {
	curve: ECDSANamedCurve;
	x: bigint;
	y: bigint;
}
```

- `curve`
- `x`
- `y`
