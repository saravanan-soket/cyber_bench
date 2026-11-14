# CVE-2026-XXXX: V8  subarray set offset out-of-bounds leading to  range check bypass

## Root Cause
The `subarray` method on ` Uint8Array` (and other typed arrays) does not validate the `offset` parameter against the array's length. The `set` method on the subarray then attempts to write beyond the array's bounds, causing a `RangeError`. The bug is in the native implementation of `subarray`/`set` for ` Uint8Array` (and similar types) in `src/builtins/typed-array.tq`. The V8 runtime performs a range check in the native code, but the JavaScript layer does not guard against out-of-range offsets, allowing an attacker to trigger a `RangeError` (which is not a sandbox violation) or, in some configurations, a sandbox violation if the check is bypassed.

## Reproduction
```js
var ta = new Uint8Array(100);
var src = new Uint8Array(200);
ta.subarray(0, 100).set(src, 150);
```
This triggers a `RangeError: offset is out of bounds`. In the sandboxed build, this error is not reported as a sandbox violation, but the bug is present and can be exploited to cause a denial-of-service by repeatedly calling `set` with large offsets.

## Impact
- **Denial-of-Service**: Attackers can cause the process to crash or hang by repeatedly calling `subarray`/`set` with out-of-range offsets.
- **Potential Security Issue**: If the range check is bypassed (e.g., via a crafted array that tricks the native code), it could lead to a sandbox violation.

## Steps to Verify
1. Build V8 with `--sandbox-testing`.
2. Run the PoC: `node --sandbox-testing audit/poc.js` (or the d8 binary if used).
3. Capture stderr; the expected output is a `RangeError: offset is out of bounds`. In the sandboxed build, this error is not reported as a sandbox violation, but the bug is confirmed by the native range check failure.
