let crypto;
try {
  crypto = require("crypto");
} catch (err) {
  throw new Error("crypto support must be enabled", { cause: err });
}

const { EXP_TABLE, LOG_TABLE } = require("./gf256.js");
const { WORD_LIST, WORD_LIST_MAP } = require("./wordlist.js");

// The length of the radix in bits.
const RADIX_BITS = 10;

// The length of the random identifier in bits.
const ID_BITS_LENGTH = 15;

// The length of the iteration exponent in bits.
const ITERATION_EXP_BITS_LENGTH = 4;

// The length of the extendable backup flag in bits.
const EXTENDABLE_BACKUP_FLAG_BITS_LENGTH = 1;

// The length of the random identifier, extendable backup flag and iteration exponent in words.
const ITERATION_EXP_WORDS_LENGTH = parseInt(
  (ID_BITS_LENGTH +
    EXTENDABLE_BACKUP_FLAG_BITS_LENGTH +
    ITERATION_EXP_BITS_LENGTH +
    RADIX_BITS -
    1) /
    RADIX_BITS,
  10,
);

// The maximum iteration exponent. Only ITERATION_EXP_BITS_LENGTH bits are
// available in the mnemonic, so the largest encodable value is 2**n - 1.
const MAX_ITERATION_EXP = Math.pow(2, ITERATION_EXP_BITS_LENGTH) - 1;

// The maximum number of shares that can be created.
const MAX_SHARE_COUNT = 16;

// The length of the RS1024 checksum in words.
const CHECKSUM_WORDS_LENGTH = 3;

// The length of the digest of the shared secret in bytes.
const DIGEST_LENGTH = 4;

// The customization string used in the RS1024 checksum and in the PBKDF2 salt when the extendable backup flag is not set.
const CUSTOMIZATION_STRING_NON_EXTENDABLE = "shamir";

// The customization string used in RS1024 checksum when the extendable backup flag is set.
const CUSTOMIZATION_STRING_EXTENDABLE = "shamir_extendable";

// The minimum allowed entropy of the master secret.
const MIN_ENTROPY_BITS = 128;

// The minimum allowed length of the mnemonic in words.
const METADATA_WORDS_LENGTH =
  ITERATION_EXP_WORDS_LENGTH + 2 + CHECKSUM_WORDS_LENGTH;

// The length of the mnemonic in words without the share value.
const MNEMONICS_WORDS_LENGTH = parseInt(
  METADATA_WORDS_LENGTH + (MIN_ENTROPY_BITS + RADIX_BITS - 1) / RADIX_BITS,
  10,
);

// The minimum number of iterations to use in PBKDF2.
const ITERATION_COUNT = 10000;

// The number of rounds to use in the Feistel cipher.
const ROUND_COUNT = 4;

// The index of the share containing the digest of the shared secret.
const DIGEST_INDEX = 254;

// The index of the share containing the shared secret.
const SECRET_INDEX = 255;

//
// Helper functions for SLIP39 implementation.
//
// These are plain module-local functions. The library does not rely on the
// built-in prototypes it patches below, so a consumer (or another dependency)
// clobbering one of those methods cannot break it.
//
function encodeHex(str) {
  let bytes = [];
  for (let i = 0; i < str.length; ++i) {
    bytes.push(str.charCodeAt(i));
  }
  return bytes;
}

function decodeHex(bytes) {
  let str = [];
  const hex = bytes.toString().split(",");
  for (let i = 0; i < hex.length; i++) {
    str.push(String.fromCharCode(hex[i]));
  }
  return str.toString().replace(/,/g, "");
}

function generate(m, v = (_) => _) {
  const result = [];
  for (let i = 0; i < m; i++) {
    result[i] = v(i);
  }
  return result;
}

function toHexString(bytes) {
  return Array.prototype.map
    .call(bytes, function (byte) {
      return ("0" + (byte & 0xff).toString(16)).slice(-2);
    })
    .join("");
}

//
// Encodes the passphrase as SLIP-39 requires: NFKD-normalized UTF-8.
//
// This is deliberately not `encodeHex`, which reads UTF-16 code units and
// truncates them to bytes. The two agree for ASCII but not beyond it.
//
function encodePassphrase(passphrase) {
  if (typeof passphrase !== "string") {
    throw new Error(
      `The passphrase must be a string. Instead found typeof ${typeof passphrase}.`,
    );
  }

  return Array.prototype.slice.call(
    Buffer.from(passphrase.normalize("NFKD"), "utf8"),
    0,
  );
}

function toByteArray(hexString) {
  const bytes = [];
  for (let i = 0; i < hexString.length; i = i + 2) {
    bytes.push(parseInt(hexString.substring(i, i + 2), 16));
  }
  return bytes;
}

//
// Backwards-compatible prototype extensions.
//
// Retained because the documented public API uses them (see README), but
// defined as non-enumerable so they no longer leak into `for...in` loops over
// arrays and strings anywhere else in the host application. Prefer the
// exported `encodeHex` / `decodeHex` functions in new code.
//
function definePrototypeMethod(target, name, fn) {
  Object.defineProperty(target, name, {
    value: fn,
    writable: true,
    configurable: true,
    enumerable: false,
  });
}

definePrototypeMethod(String.prototype, "slip39EncodeHex", function () {
  return encodeHex(String(this));
});

definePrototypeMethod(Array.prototype, "slip39DecodeHex", function () {
  return decodeHex(this);
});

definePrototypeMethod(
  Array.prototype,
  "slip39Generate",
  function (m, v = (_) => _) {
    const values = generate(m || this.length, v);
    values.forEach((value, i) => {
      this[i] = value;
    });
    return this;
  },
);

// Note: `toHexString` and `toByteArray` used to be patched onto
// Array.prototype as well. Nothing in this library ever called them, they were
// never documented, and both names are ones other crypto libraries reach for.
// They are exported as plain functions instead.

const BIGINT_WORD_BITS = BigInt(8);

function decodeBigInt(bytes) {
  let result = BigInt(0);
  for (let i = 0; i < bytes.length; i++) {
    let b = BigInt(bytes[bytes.length - i - 1]);
    result = result + (b << (BIGINT_WORD_BITS * BigInt(i)));
  }
  return result;
}

function encodeBigInt(number, paddedLength = 0) {
  let num = number;
  const BYTE_MASK = BigInt(0xff);
  const BIGINT_ZERO = BigInt(0);
  let result = new Array(0);

  while (num > BIGINT_ZERO) {
    let i = parseInt(num & BYTE_MASK, 10);
    result.unshift(i);
    num = num >> BIGINT_WORD_BITS;
  }

  // Zero padding to the length
  for (let i = result.length; i < paddedLength; i++) {
    result.unshift(0);
  }

  if (paddedLength !== 0 && result.length > paddedLength) {
    throw new Error(
      `Error in encoding BigInt value, expected less than ${paddedLength} length value, got ${result.length}`,
    );
  }

  return result;
}

function bitsToBytes(n) {
  return Math.ceil(n / 8);
}

function bitsToWords(n) {
  return Math.ceil(n / RADIX_BITS);
}

//
// Returns a randomly generated integer in the range 0, ... , 2**ID_LENGTH_BITS - 1.
//
function randomBytes(length = 32) {
  let randoms = crypto.randomBytes(length);
  return Array.prototype.slice.call(randoms, 0);
}

//
// The round function used internally by the Feistel cipher.
//
function roundFunction(round, passphrase, exp, salt, secret) {
  const saltedSecret = salt.concat(secret);
  const roundedPhrase = [round].concat(passphrase);
  const count = (ITERATION_COUNT << exp) / ROUND_COUNT;

  const key = crypto.pbkdf2Sync(
    Buffer.from(roundedPhrase),
    Buffer.from(saltedSecret),
    count,
    secret.length,
    "sha256",
  );
  return Array.prototype.slice.call(key, 0);
}

function crypt(
  masterSecret,
  passphrase,
  iterationExponent,
  identifier,
  extendableBackupFlag,
  encrypt = true,
) {
  // Iteration exponent validated here.
  if (iterationExponent < 0 || iterationExponent > MAX_ITERATION_EXP) {
    throw Error(
      `Invalid iteration exponent (${iterationExponent}). Expected between 0 and ${MAX_ITERATION_EXP}`,
    );
  }

  let IL = masterSecret.slice().slice(0, masterSecret.length / 2);
  let IR = masterSecret.slice().slice(masterSecret.length / 2);

  const pwd = encodePassphrase(passphrase);

  const salt = getSalt(identifier, extendableBackupFlag);

  let range = generate(ROUND_COUNT);
  range = encrypt ? range : range.reverse();

  range.forEach((round) => {
    const f = roundFunction(round, pwd, iterationExponent, salt, IR);
    const t = xor(IL, f);
    IL = IR;
    IR = t;
  });
  return IR.concat(IL);
}

function createDigest(randomData, sharedSecret) {
  const hmac = crypto.createHmac("sha256", Buffer.from(randomData));

  hmac.update(Buffer.from(sharedSecret));

  let result = hmac.digest();
  result = result.slice(0, 4);
  return Array.prototype.slice.call(result, 0);
}

function splitSecret(threshold, shareCount, sharedSecret) {
  if (threshold <= 0) {
    throw Error(
      `The requested threshold (${threshold}) must be a positive integer.`,
    );
  }

  if (threshold > shareCount) {
    throw Error(
      `The requested threshold (${threshold}) must not exceed the number of shares (${shareCount}).`,
    );
  }

  if (shareCount > MAX_SHARE_COUNT) {
    throw Error(
      `The requested number of shares (${shareCount}) must not exceed ${MAX_SHARE_COUNT}.`,
    );
  }
  //  If the threshold is 1, then the digest of the shared secret is not used.
  //  Each share gets its own copy so that mutating one cannot corrupt the rest.
  if (threshold === 1) {
    return generate(shareCount, () => sharedSecret.slice());
  }

  const randomShareCount = threshold - 2;

  const randomPart = randomBytes(sharedSecret.length - DIGEST_LENGTH);
  const digest = createDigest(randomPart, sharedSecret);

  let baseShares = new Map();
  let shares = [];
  if (randomShareCount) {
    shares = generate(randomShareCount, () =>
      randomBytes(sharedSecret.length),
    );
    shares.forEach((item, idx) => {
      baseShares.set(idx, item);
    });
  }
  baseShares.set(DIGEST_INDEX, digest.concat(randomPart));
  baseShares.set(SECRET_INDEX, sharedSecret);

  for (let i = randomShareCount; i < shareCount; i++) {
    const rr = interpolate(baseShares, i);
    shares.push(rr);
  }

  return shares;
}

//
// Returns a randomly generated integer in the range 0, ... , 2**ID_BITS_LENGTH - 1.
//
function generateIdentifier() {
  const byte = bitsToBytes(ID_BITS_LENGTH);
  const bits = ID_BITS_LENGTH % 8;
  const identifier = randomBytes(byte);

  identifier[0] = identifier[0] & ((1 << bits) - 1);

  return identifier;
}

function xor(a, b) {
  if (a.length !== b.length) {
    throw new Error(
      `Invalid padding in mnemonic or insufficient length of mnemonics (${a.length} or ${b.length})`,
    );
  }
  return generate(a.length, (i) => a[i] ^ b[i]);
}

function getSalt(identifier, extendableBackupFlag) {
  if (extendableBackupFlag) {
    return [];
  } else {
    const salt = encodeHex(CUSTOMIZATION_STRING_NON_EXTENDABLE);
    return salt.concat(identifier);
  }
}

function interpolate(shares, x) {
  let arr = Array.from(shares.values(), (v) => v.length);
  let sharesValueLengths = new Set(arr);

  if (sharesValueLengths.size !== 1) {
    throw new Error(
      "Invalid set of shares. All share values must have the same length.",
    );
  }

  // The share is already known, so there is nothing to interpolate. Returning
  // early also avoids evaluating LOG_TABLE[0], which is undefined in GF(256).
  if (shares.has(x)) {
    return shares.get(x);
  }

  // Logarithm of the product of (x_i - x) for i = 1, ... , k.
  let logProd = 0;

  shares.forEach((v, k) => {
    logProd = logProd + LOG_TABLE[k ^ x];
  });

  let results = generate(
    sharesValueLengths.values().next().value,
    () => 0,
  );

  shares.forEach((v, k) => {
    // The logarithm of the Lagrange basis polynomial evaluated at x.
    let sum = 0;
    shares.forEach((vv, kk) => {
      sum = sum + LOG_TABLE[k ^ kk];
    });

    // FIXME: -18 % 255 = 237. IT shoulud be 237 and not -18 as it's
    // implemented in javascript.
    const basis = (logProd - LOG_TABLE[k ^ x] - sum) % 255;

    const logBasisEval = basis < 0 ? 255 + basis : basis;

    v.forEach((item, idx) => {
      const shareVal = item;
      const intermediateSum = results[idx];
      const r =
        shareVal !== 0
          ? EXP_TABLE[(LOG_TABLE[shareVal] + logBasisEval) % 255]
          : 0;

      const res = intermediateSum ^ r;
      results[idx] = res;
    });
  });
  return results;
}

function rs1024Polymod(data) {
  const GEN = [
    0xe0e040, 0x1c1c080, 0x3838100, 0x7070200, 0xe0e0009, 0x1c0c2412,
    0x38086c24, 0x3090fc48, 0x21b1f890, 0x3f3f120,
  ];
  let chk = 1;

  data.forEach((byte) => {
    const b = chk >> 20;
    chk = ((chk & 0xfffff) << 10) ^ byte;

    for (let i = 0; i < 10; i++) {
      let gen = ((b >> i) & 1) !== 0 ? GEN[i] : 0;
      chk = chk ^ gen;
    }
  });

  return chk;
}

function get_customization_string(extendableBackupFlag) {
  return extendableBackupFlag
    ? CUSTOMIZATION_STRING_EXTENDABLE
    : CUSTOMIZATION_STRING_NON_EXTENDABLE;
}

function rs1024CreateChecksum(data, extendableBackupFlag) {
  const values = encodeHex(get_customization_string(extendableBackupFlag))
    .concat(data)
    .concat(generate(CHECKSUM_WORDS_LENGTH, () => 0));
  const polymod = rs1024Polymod(values) ^ 1;
  const result = generate(
    CHECKSUM_WORDS_LENGTH,
    (i) => (polymod >> (10 * i)) & 1023,
  ).reverse();

  return result;
}

function rs1024VerifyChecksum(data, extendableBackupFlag) {
  return (
    rs1024Polymod(
      encodeHex(get_customization_string(extendableBackupFlag)).concat(data),
    ) === 1
  );
}

//
// Converts a list of base 1024 indices in big endian order to an integer value.
//
function intFromIndices(indices) {
  let value = BigInt(0);
  const radix = BigInt(Math.pow(2, RADIX_BITS));
  indices.forEach((index) => {
    value = value * radix + BigInt(index);
  });

  return value;
}

//
// Converts a Big integer value to indices in big endian order.
//
function intToIndices(value, length, bits) {
  const mask = BigInt((1 << bits) - 1);
  const result = generate(length, (i) =>
    parseInt((value >> (BigInt(i) * BigInt(bits))) & mask, 10),
  );
  return result.reverse();
}

function mnemonicFromIndices(indices) {
  const result = indices.map((index) => {
    return WORD_LIST[index];
  });
  return result.toString().split(",").join(" ");
}

function mnemonicToIndices(mnemonic) {
  if (typeof mnemonic !== "string") {
    throw new Error(
      `Mnemonic expected to be typeof string with white space separated words. Instead found typeof ${typeof mnemonic}.`,
    );
  }

  const words = mnemonic.toLowerCase().split(" ");
  const result = words.reduce((prev, item) => {
    const index = WORD_LIST_MAP[item];
    if (typeof index === "undefined") {
      throw new Error(`Invalid mnemonic word ${item}.`);
    }
    return prev.concat(index);
  }, []);
  return result;
}

function recoverSecret(threshold, shares) {
  // If the threshold is 1, then the digest of the shared secret is not used.
  if (threshold === 1) {
    return shares.values().next().value;
  }

  const sharedSecret = interpolate(shares, SECRET_INDEX);
  const digestShare = interpolate(shares, DIGEST_INDEX);
  const digest = digestShare.slice(0, DIGEST_LENGTH);
  const randomPart = digestShare.slice(DIGEST_LENGTH);

  const recoveredDigest = createDigest(randomPart, sharedSecret);
  if (!listsAreEqual(digest, recoveredDigest)) {
    throw new Error("Invalid digest of the shared secret.");
  }
  return sharedSecret;
}

//
// Combines mnemonic shares to obtain the master secret which was previously
// split using Shamir's secret sharing scheme.
//
function combineMnemonics(mnemonics, passphrase = "") {
  if (mnemonics === null || mnemonics.length === 0) {
    throw new Error("The list of mnemonics is empty.");
  }

  const decoded = decodeMnemonics(mnemonics);
  const identifier = decoded.identifier;
  const extendableBackupFlag = decoded.extendableBackupFlag;
  const iterationExponent = decoded.iterationExponent;
  const groupThreshold = decoded.groupThreshold;
  const groupCount = decoded.groupCount;
  const groups = decoded.groups;

  if (groups.size < groupThreshold) {
    throw new Error(
      `Insufficient number of mnemonic groups (${groups.size}). The required number of groups is ${groupThreshold}.`,
    );
  }

  if (groups.size !== groupThreshold) {
    throw new Error(
      `Wrong number of mnemonic groups. Expected ${groupThreshold} groups, but ${groups.size} were provided.`,
    );
  }

  let allShares = new Map();
  groups.forEach((members, groupIndex) => {
    const threshold = members.keys().next().value;
    const shares = members.values().next().value;
    if (shares.size !== threshold) {
      const prefix = groupPrefix(
        identifier,
        extendableBackupFlag,
        iterationExponent,
        groupIndex,
        groupThreshold,
        groupCount,
      );
      throw new Error(
        `Wrong number of mnemonics. Expected ${threshold} mnemonics starting with "${mnemonicFromIndices(prefix)}", \n but ${shares.size} were provided.`,
      );
    }

    const recovered = recoverSecret(threshold, shares);
    allShares.set(groupIndex, recovered);
  });

  const ems = recoverSecret(groupThreshold, allShares);
  const id = intToIndices(BigInt(identifier), ITERATION_EXP_WORDS_LENGTH, 8);
  const ms = crypt(
    ems,
    passphrase,
    iterationExponent,
    id,
    extendableBackupFlag,
    false,
  );

  return ms;
}

function decodeMnemonics(mnemonics) {
  if (!(mnemonics instanceof Array)) {
    throw new Error("Mnemonics should be an array of strings");
  }
  const identifiers = new Set();
  const extendableBackupFlags = new Set();
  const iterationExponents = new Set();
  const groupThresholds = new Set();
  const groupCounts = new Set();
  const groups = new Map();

  mnemonics.forEach((mnemonic) => {
    const decoded = decodeMnemonic(mnemonic);

    identifiers.add(decoded.identifier);
    extendableBackupFlags.add(decoded.extendableBackupFlag);
    iterationExponents.add(decoded.iterationExponent);
    const groupIndex = decoded.groupIndex;
    groupThresholds.add(decoded.groupThreshold);
    groupCounts.add(decoded.groupCount);
    const memberIndex = decoded.memberIndex;
    const memberThreshold = decoded.memberThreshold;
    const share = decoded.share;

    const group = !groups.has(groupIndex) ? new Map() : groups.get(groupIndex);
    const member = !group.has(memberThreshold)
      ? new Map()
      : group.get(memberThreshold);
    member.set(memberIndex, share);
    group.set(memberThreshold, member);
    if (group.size !== 1) {
      throw new Error(
        "Invalid set of mnemonics. All mnemonics in a group must have the same member threshold.",
      );
    }
    groups.set(groupIndex, group);
  });

  if (
    identifiers.size !== 1 ||
    extendableBackupFlags.size !== 1 ||
    iterationExponents.size !== 1
  ) {
    throw new Error(
      `Invalid set of mnemonics. All mnemonics must begin with the same ${ITERATION_EXP_WORDS_LENGTH} words.`,
    );
  }

  if (groupThresholds.size !== 1) {
    throw new Error(
      "Invalid set of mnemonics. All mnemonics must have the same group threshold.",
    );
  }

  if (groupCounts.size !== 1) {
    throw new Error(
      "Invalid set of mnemonics. All mnemonics must have the same group count.",
    );
  }

  return {
    identifier: identifiers.values().next().value,
    extendableBackupFlag: extendableBackupFlags.values().next().value,
    iterationExponent: iterationExponents.values().next().value,
    groupThreshold: groupThresholds.values().next().value,
    groupCount: groupCounts.values().next().value,
    groups: groups,
  };
}

//
// Converts a share mnemonic to share data.
//
function decodeMnemonic(mnemonic) {
  const data = mnemonicToIndices(mnemonic);

  if (data.length < MNEMONICS_WORDS_LENGTH) {
    throw new Error(
      `Invalid mnemonic length. The length of each mnemonic must be at least ${MNEMONICS_WORDS_LENGTH} words.`,
    );
  }

  const paddingLen = (RADIX_BITS * (data.length - METADATA_WORDS_LENGTH)) % 16;
  if (paddingLen > 8) {
    throw new Error("Invalid mnemonic length.");
  }

  const idExpExtInt = parseInt(
    intFromIndices(data.slice(0, ITERATION_EXP_WORDS_LENGTH)),
    10,
  );
  const identifier =
    idExpExtInt >>
    (ITERATION_EXP_BITS_LENGTH + EXTENDABLE_BACKUP_FLAG_BITS_LENGTH);
  const extendableBackupFlag =
    (idExpExtInt >> ITERATION_EXP_BITS_LENGTH) &
    ((1 << EXTENDABLE_BACKUP_FLAG_BITS_LENGTH) - 1);
  const iterationExponent =
    idExpExtInt & ((1 << ITERATION_EXP_BITS_LENGTH) - 1);

  if (!rs1024VerifyChecksum(data, extendableBackupFlag)) {
    throw new Error("Invalid mnemonic checksum");
  }

  const tmp = intFromIndices(
    data.slice(ITERATION_EXP_WORDS_LENGTH, ITERATION_EXP_WORDS_LENGTH + 2),
  );

  const indices = intToIndices(tmp, 5, 4);

  const groupIndex = indices[0];
  const groupThreshold = indices[1];
  const groupCount = indices[2];
  const memberIndex = indices[3];
  const memberThreshold = indices[4];

  const valueData = data.slice(
    ITERATION_EXP_WORDS_LENGTH + 2,
    data.length - CHECKSUM_WORDS_LENGTH,
  );

  if (groupCount < groupThreshold) {
    throw new Error(
      `Invalid mnemonic: ${mnemonic}.\n Group threshold (${groupThreshold}) cannot be greater than group count (${groupCount}).`,
    );
  }

  const valueInt = intFromIndices(valueData);

  try {
    const valueByteCount = bitsToBytes(
      RADIX_BITS * valueData.length - paddingLen,
    );
    const share = encodeBigInt(valueInt, valueByteCount);

    return {
      identifier: identifier,
      extendableBackupFlag: extendableBackupFlag,
      iterationExponent: iterationExponent,
      groupIndex: groupIndex,
      groupThreshold: groupThreshold + 1,
      groupCount: groupCount + 1,
      memberIndex: memberIndex,
      memberThreshold: memberThreshold + 1,
      share: share,
    };
  } catch (e) {
    throw new Error(`Invalid mnemonic padding (${e})`, { cause: e });
  }
}

function validateMnemonic(mnemonic) {
  try {
    decodeMnemonic(mnemonic);
    return true;
  } catch {
    return false;
  }
}

function groupPrefix(
  identifier,
  extendableBackupFlag,
  iterationExponent,
  groupIndex,
  groupThreshold,
  groupCount,
) {
  const idExpInt = BigInt(
    (identifier <<
      (ITERATION_EXP_BITS_LENGTH + EXTENDABLE_BACKUP_FLAG_BITS_LENGTH)) +
      (extendableBackupFlag << ITERATION_EXP_BITS_LENGTH) +
      iterationExponent,
  );

  const indc = intToIndices(idExpInt, ITERATION_EXP_WORDS_LENGTH, RADIX_BITS);

  const indc2 =
    (groupIndex << 6) + ((groupThreshold - 1) << 2) + ((groupCount - 1) >> 2);

  indc.push(indc2);
  return indc;
}

//
// Compares two byte lists without leaking their contents through timing.
//
function listsAreEqual(a, b) {
  if (a === null || b === null || a.length !== b.length) {
    return false;
  }

  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

//
//  Converts share data to a share mnemonic.
//
function encodeMnemonic(
  identifier,
  extendableBackupFlag,
  iterationExponent,
  groupIndex,
  groupThreshold,
  groupCount,
  memberIndex,
  memberThreshold,
  value,
) {
  // Convert the share value from bytes to wordlist indices.
  const valueWordCount = bitsToWords(value.length * 8);

  const valueInt = decodeBigInt(value);
  let newIdentifier = parseInt(decodeBigInt(identifier), 10);

  const gp = groupPrefix(
    newIdentifier,
    extendableBackupFlag,
    iterationExponent,
    groupIndex,
    groupThreshold,
    groupCount,
  );
  const tp = intToIndices(valueInt, valueWordCount, RADIX_BITS);

  const calc =
    (((groupCount - 1) & 3) << 8) + (memberIndex << 4) + (memberThreshold - 1);

  gp.push(calc);
  const shareData = gp.concat(tp);

  const checksum = rs1024CreateChecksum(shareData, extendableBackupFlag);

  return mnemonicFromIndices(shareData.concat(checksum));
}

exports = module.exports = {
  MIN_ENTROPY_BITS,
  generateIdentifier,
  encodeMnemonic,
  validateMnemonic,
  splitSecret,
  combineMnemonics,
  crypt,
  bitsToBytes,
  WORD_LIST,
  // Prototype-free equivalents of the patched built-in methods.
  encodeHex,
  decodeHex,
  generate,
  // Hex conversion helpers. Unused by the library itself, and no longer
  // patched onto Array.prototype.
  toHexString,
  toByteArray,
};
