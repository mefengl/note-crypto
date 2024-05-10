---
title: "alphabet()"
---

# alphabet()

Returns a string with all the characters defined in the provided pattern:

- `a-z`: `abcdefghijklmnopqrstuvwxyz`
- `A-Z`: `ABCDEFGHIJKLMNOPqRSTUVWXYZ`
- `0-9`: `0123456789`
- `-`: Character `-`
- `_`: Character `_`

## Definition

```ts
//$ AlphabetPattern=/reference/random/AlphabetPattern
function alphabet(...patterns: $$AlphabetPattern[]): string;
```

### Parameters

- `patterns`

## Example

```ts
import { alphabet } from "oslo/crypto";

// "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPqRSTUVWXYZ0123456789"
alphabet("a-z", "A-Z", "0-9");

// "0123456789"
alphabet("0-9", "0-9");
```
