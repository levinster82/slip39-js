v0.1.0

- Initial release

v0.1.1

- Code clean up and addes some unit tests

v0.1.2

- Added length to encodeBigInt()

v0.1.5-dev.1

- Bumped version, changed versioning format

v0.1.5

- Bumped version
- Added nodejs.yml
- Merge pull requests from different contributors

v0.1.6

- Fixed ilap/slip39-js#12
- Some cosmetic fixes

v0.1.7

- Merge pull requests from different contributors
- Fixed ilap/slip39-js#14
- Fixed ilap/slip39-js#18

v0.1.8

- for the `extendable backup flag`. See details in the recent [revision](https://github.com/satoshilabs/slips/commit/8d060706b549af6443e04f55605b71f65c981663?short_path=ee22765#diff-ee22765e198171085aada68244108cf54a020b79e69e67440854e27a4a927f04) of the [SLIP-39 specification](https://github.com/satoshilabs/slips/blob/master/slip-0039.md).%

v0.1.9

- feat: Exported word list.

v0.4.0-levinster82.1

Features

- `Slip39.fromJson(masterSecret, json, options?)` builds a share tree from a
  JSON description, which additionally names each individual share. Accepts an
  object or a JSON string. This implements the long-standing README TODO.

  The shape matches the author's Dart implementation, so one configuration
  works in both. SLIP-39 defines no JSON format and Trezor's reference
  implementation has no notion of naming groups or shares, so names are local
  metadata: never encoded into the mnemonics, no effect on the cryptography.

- `slip.toJson(options?)` serialises the tree back to the same shape, so
  `fromJson(ms, config).toJson()` deep-equals `config`. Mnemonics are omitted
  by default so that logging or stringifying a Slip39 cannot leak seeds;
  `toJson({ mnemonics: true })` includes them and is secret material.

- `Slip39Node` gained a `threshold` property, recording how many members a
  group needs, so the tree can be serialised. 0 on leaves and on the root.

- Leaf nodes now carry their own `description` when built via `fromJson`.
  Trees built with `fromArray` are unchanged: members still inherit the
  group's description.

v0.3.0-levinster82.1

Breaking

- `Array.prototype.toHexString` and `Array.prototype.toByteArray` are no longer
  patched onto the built-in prototype. Neither was used by the library nor
  documented, and both names collide readily with other crypto packages. The
  functionality is exported from `src/slip39_helper.js` instead:

      const { toHexString, toByteArray } = require("slip39/src/slip39_helper");
      toHexString([255, 1]); // "ff01"
      toByteArray("ff01");   // [255, 1]

  `toByteArray` now takes just the hex string and returns a new array, rather
  than appending to the array it was called on.

- `slip39EncodeHex`, `slip39DecodeHex` and `slip39Generate` are unaffected and
  remain on the prototypes.

v0.2.0-levinster82.1

Fork release, not published to npm. The `slip39` package on npm is maintained
by ilap and remains at v0.1.9; this fork is consumed directly from git. The
`-levinster82` suffix keeps the version from ever colliding with an upstream
release.

Fixes

- **`iterationExponent: 16` produced unrecoverable shares.** Only 4 bits are
  available for the exponent, so 16 overflowed into the extendable backup flag
  and every generated share failed its checksum on recovery. Values above 15
  are now rejected. Shares created with `16` were never recoverable.
- Passphrases are now encoded as NFKD-normalized UTF-8 as the specification
  requires, instead of raw UTF-16 code units truncated to bytes. ASCII
  passphrases are byte-for-byte unchanged; non-ASCII ones now interoperate with
  other SLIP-39 implementations and are no longer rejected by `fromArray`.
- `interpolate()` no longer falls through to a `log(0)` lookup when asked for an
  x-coordinate it already holds.
- `bitsToBytes()` / `bitsToWords()` no longer pass `RADIX_BITS` as `parseInt`'s
  radix argument, which happened to work only because it equals 10.
- `splitSecret()` with a threshold of 1 returns independent copies rather than
  many references to one array.
- The shared-secret digest is now compared with `crypto.timingSafeEqual`.

Compatibility

- The `String.prototype` / `Array.prototype` extensions are unchanged and still
  work, but are now defined as **non-enumerable**, so they no longer leak into
  `for...in` loops over arrays and strings in the host application. Equivalent
  `encodeHex` / `decodeHex` / `generate` functions are exported from
  `src/slip39_helper.js` for code that would rather not rely on them.

Tooling

- Added TypeScript declarations (`index.d.ts`).
- Added a `files` allowlist; the published tarball no longer carries tests,
  examples, or CI config.
- Replaced the never-runnable `.eslintrc.js` with a flat `eslint.config.js`,
  added eslint as a devDependency and `npm run lint`.
- `package-lock.json` is now tracked and CI installs with `npm ci`.
- CI actions updated to v4; Node matrix is now 20/22/24.