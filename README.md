# SLIP39

[![npm](https://img.shields.io/npm/v/slip39.svg)](https://www.npmjs.org/package/slip39)

The javascript implementation of the [SLIP39](https://github.com/satoshilabs/slips/blob/master/slip-0039.md) for Shamir's Secret-Sharing for Mnemonic Codes.

The code based on my [Dart implementation of SLIP-0039](https://github.com/ilap/slip39-dart/).

# DISCLAIMER

This project is still in early development phase. Use it at your own risk.

## Description

This SLIP39 implementation uses a 3 level height (l=3) of a 16 degree (d=16) tree (T), which is represented as an array of the level two nodes (groups, G).

The degree (d) and the level (l) of the tree are 16 and 3 respectively,
which means that max d^(l-1), i.e. 16^2, leaf nodes (M) can be in a complete tree (or forest).

The first level (l=1) node of the tree is the root (R), the level 2 ones are the `SSS` groups (Gs or group nodes) e.g. `[G0, ..., Gd]`.

The last, the third, level nodes are the only leaves (M, group members) which contain the generated mnemonics.

Every node has two values:

- the N and
- M i.e. n(N,M).

Which means, that N (`threshold`) number of M children are required to reconstruct the node's secret.

## Format

The tree's human friendly array representation only uses the group (l=2) nodes as arrays.
For example: ` [[1,1], [1,1], [3,5], [2,6]]`
The group's first parameter is the `N` (group threshold) while the second is the `M`, the number of members in the group. See, and example in [Using](#Using).

## Installing

```
npm install slip39

```

## Using

See `example/main.js`

```javascript
const slip39 = require("../src/slip39.js");
const assert = require("assert");
// threshold (N) number of group shares required to reconstruct the master secret.
const threshold = 2;
const masterSecret = "ABCDEFGHIJKLMNOP".slip39EncodeHex();
const passphrase = "TREZOR";

/**
 * 4 groups shares.
 * = two for Alice
 * = one for friends and
 * = one for family members
 * Two of these group shares are required to reconstruct the master secret.
 */
const groups = [
  // Alice group shares. 1 is enough to reconstruct a group share,
  // therefore she needs at least two group shares to be reconstructed,
  [1, 1],
  [1, 1],
  // 3 of 5 Friends' shares are required to reconstruct this group share
  [3, 5],
  // 2 of 6 Family's shares are required to reconstruct this group share
  [2, 6],
];

const slip = slip39.fromArray(masterSecret, {
  passphrase: passphrase,
  threshold: threshold,
  groups: groups,
});

// One of Alice's share
const aliceShare = slip.fromPath("r/0").mnemonics;

// and any two of family's shares.
const familyShares = slip
  .fromPath("r/3/1")
  .mnemonics.concat(slip.fromPath("r/3/3").mnemonics);

const allShares = aliceShare.concat(familyShares);

console.log("Shares used for restoring the master secret:");
allShares.forEach((s) => console.log(s));

const recoveredSecret = slip39.recoverSecret(allShares, passphrase);
console.log("Master secret: " + masterSecret.slip39DecodeHex());
console.log("Recovered one: " + recoveredSecret.slip39DecodeHex());
assert(masterSecret.slip39DecodeHex() === recoveredSecret.slip39DecodeHex());
```

## API

### `Slip39.fromArray(masterSecret, options?)`

Splits `masterSecret` (an array of byte values, at least 16 bytes and of even
length) into a share tree. Options:

| Option | Default | Meaning |
| --- | --- | --- |
| `passphrase` | `""` | Encrypts the master secret. NFKD UTF-8 encoded. |
| `threshold` | `1` | Number of group shares needed to reconstruct the secret. |
| `groups` | `[[1, 1, "..."]]` | Group specs, `[threshold, members, description?]`. |
| `iterationExponent` | `0` | PBKDF2 work factor, `0` to `15` inclusive. |
| `extendableBackupFlag` | `1` | Set the [extendable backup flag](https://github.com/satoshilabs/slips/blob/master/slip-0039.md). |
| `title` | `"My default slip39 shares"` | Description of the whole set. |

### `Slip39.recoverSecret(mnemonics, passphrase?)`

Recombines an array of mnemonic strings into the master secret, as an array of
byte values. Throws if the set is insufficient, inconsistent, or corrupt.

### `Slip39.validateMnemonic(mnemonic)`

Returns whether a single mnemonic string is well formed, without attempting
recovery.

### `slip.fromPath(path)`

Returns the node at `path` (`"r"`, `"r/0"`, `"r/3/1"`). Each node exposes
`description`, `children`, and `mnemonics`.

### Word list

The SLIP-39 word list is exported from the helper module:

```javascript
const { WORD_LIST } = require("slip39/src/slip39_helper");
```

## Notes and caveats

- **Passphrases** are encoded as NFKD-normalized UTF-8, per the specification.
  SLIP-39 recommends restricting them to printable ASCII (code points 32-126)
  for the widest interoperability with other implementations; anything outside
  that range is accepted here but may not be portable.
- **Secrets are not zeroized.** Master secrets and intermediate shares live in
  ordinary JavaScript arrays, which cannot be reliably wiped from memory. This
  is a limitation of the runtime, not something the library can work around.
- **`slip39EncodeHex`, `slip39DecodeHex` and `slip39Generate` patch the
  built-in prototypes.** They are kept for backwards compatibility and are
  defined as non-enumerable, so they do not appear in `for...in` loops. New
  code should prefer the exported `encodeHex` / `decodeHex` / `generate`
  functions from the helper module.
- **`toHexString` and `toByteArray` are no longer on `Array.prototype`.** They
  were never used by the library or documented, and both names collide easily.
  They are exported from the helper module instead:

  ```javascript
  const { toHexString, toByteArray } = require("slip39/src/slip39_helper");

  toHexString([255, 1]); // "ff01"
  toByteArray("ff01"); // [255, 1]
  ```

## Testing

```bash
 $ npm install
 $ npm test
```

The suite covers the official SLIP-39 test vectors along with group, path, and
validation cases.

## Linting

```bash
 $ npm run lint
```

## TODOS

- [x] Add unit tests.
- [x] Test with the reference code's test vectors.
- [ ] Refactor the helpers.
  - [x] Split the word list and the GF(256) exponent/log tables out of
        `slip39_helper.js` into `src/wordlist.js` and `src/gf256.js`, taking
        that file from 1955 lines down to 872 lines of logic.
  - [x] Replace the built-in prototype patching with plain functions
        internally, keeping the old methods as non-enumerable shims.
  - [ ] The original `CryptoHelper()` / `ShamirHelper()` class split was
        deliberately not adopted: these are pure functions, and wrapping them
        in classes would add indirection without adding structure. Open
        question whether any further grouping is worth doing.
- [ ] Add `JSON` representation, see [JSON representation](#json-representation) below.
- [ ] Refactor to much simpler code.

### JSON Representation

```json
{
  "name": "Slip39",
  "threshold": 2,
  "shares": [
    {
      "name": "My Primary",
      "threshold": 1,
      "shares": ["Primary"]
    },
    {
      "name": "My Secondary",
      "threshold": 1,
      "shares": ["Secondary"]
    },
    {
      "name": "Friends",
      "threshold": 3,
      "shares": ["Alice", "Bob", "Charlie", "David", "Erin"]
    },
    {
      "name": "Family",
      "threshold": 2,
      "shares": ["Adam", "Brenda", "Carol", "Dan", "Edward", "Frank"]
    }
  ]
}
```

# LICENSE

CopyRight (c) 2019 Pal Dorogi `"iLap"` <pal.dorogi@gmail.com>

[MIT License](LICENSE)
