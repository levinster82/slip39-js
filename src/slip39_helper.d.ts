// Type definitions for the slip39 low-level helpers.
//
// These are internal to the library and are not covered by semver in the way
// the main entry point is. They are typed because the SLIP-39 word list is
// documented as a public export.

/** The minimum allowed entropy of the master secret, in bits. */
export declare const MIN_ENTROPY_BITS: number;

/** The 1024-word SLIP-39 word list, ordered by index. */
export declare const WORD_LIST: string[];

export declare function generateIdentifier(): number[];

export declare function encodeMnemonic(
  identifier: number[],
  extendableBackupFlag: number,
  iterationExponent: number,
  groupIndex: number,
  groupThreshold: number,
  groupCount: number,
  memberIndex: number,
  memberThreshold: number,
  value: number[],
): string;

export declare function validateMnemonic(mnemonic: string): boolean;

export declare function splitSecret(
  threshold: number,
  shareCount: number,
  sharedSecret: number[],
): number[][];

export declare function combineMnemonics(
  mnemonics: string[],
  passphrase?: string,
): number[];

export declare function crypt(
  masterSecret: number[],
  passphrase: string,
  iterationExponent: number,
  identifier: number[],
  extendableBackupFlag: number,
  encrypt?: boolean,
): number[];

export declare function bitsToBytes(n: number): number;

/** Byte values of a string's UTF-16 code units. Prototype-free equivalent of `String#slip39EncodeHex`. */
export declare function encodeHex(str: string): number[];

/** Interprets byte values as a string. Prototype-free equivalent of `Array#slip39DecodeHex`. */
export declare function decodeHex(bytes: number[]): string;

/** Builds an array of `m` values produced by `v`. */
export declare function generate<T>(m: number, v?: (i: number) => T): T[];
