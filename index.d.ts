// Type definitions for slip39
// Project: https://github.com/ilap/slip39-js

export = Slip39;

/**
 * A group specification: `[threshold, memberCount, description?]`.
 *
 * `threshold` members out of `memberCount` are required to reconstruct the
 * group's share. A threshold of 1 is only valid with a single member.
 */
type Slip39Group = [number, number] | [number, number, string];

interface Slip39Options {
  /** Passphrase used to encrypt the master secret. NFKD UTF-8 encoded. */
  passphrase?: string;
  /** Number of group shares required to reconstruct the master secret. */
  threshold?: number;
  /** The groups to split the master secret into. */
  groups?: Slip39Group[];
  /** PBKDF2 iteration exponent, 0 to 15 inclusive. */
  iterationExponent?: number;
  /** Extendable backup flag, 0 or 1. Defaults to 1. */
  extendableBackupFlag?: number;
  /** Description of the whole share set. */
  title?: string;
}

/**
 * A node in the share tree. The root is the whole set, level-two nodes are the
 * groups, and the leaves carry the generated mnemonics.
 */
declare class Slip39Node {
  constructor(
    index?: number,
    description?: string,
    mnemonic?: string,
    children?: Slip39Node[],
  );

  index: number;
  description: string;
  mnemonic: string;
  children: Slip39Node[];

  /** Every mnemonic at or below this node. */
  readonly mnemonics: string[];
}

declare class Slip39 {
  constructor(options?: {
    iterationExponent?: number;
    extendableBackupFlag?: number;
    identifier?: number[];
    groupCount?: number;
    groupThreshold?: number;
  });

  iterationExponent: number;
  extendableBackupFlag: number;
  identifier: number[];
  groupCount: number;
  groupThreshold: number;
  root: Slip39Node;

  /**
   * Splits a master secret into mnemonic shares.
   *
   * @param masterSecret Byte values. At least 16 bytes, and an even length.
   */
  static fromArray(masterSecret: number[], options?: Slip39Options): Slip39;

  /** Recombines mnemonic shares into the original master secret. */
  static recoverSecret(mnemonics: string[], passphrase?: string): number[];

  /** Returns whether a single mnemonic is well formed. */
  static validateMnemonic(mnemonic: string): boolean;

  /** Looks up a node by path, e.g. `"r"`, `"r/0"`, `"r/3/1"`. */
  fromPath(path: string): Slip39Node;

  /** Throws if the path is malformed or exceeds the maximum depth. */
  validatePath(path: string): void;

  /** Parses the numeric child indices out of a path. */
  parseChildren(path: string): number[];
}

declare global {
  interface String {
    /** Byte values of this string's UTF-16 code units. */
    slip39EncodeHex(): number[];
  }

  interface Array<T> {
    /** Interprets the array as byte values and returns the string. */
    slip39DecodeHex(): string;
    /** Fills the array with `m` values produced by `v`, and returns it. */
    slip39Generate(m: number, v?: (i: number) => unknown): T[];
    /** Lowercase hex representation of the array's byte values. */
    toHexString(): string;
    /** Appends the bytes of a hex string to the array, and returns it. */
    toByteArray(hexString: string): number[];
  }
}
