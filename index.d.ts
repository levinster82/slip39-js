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
 * A JSON description of a share tree, matching the shape used by the sibling
 * Dart implementation. The outer `shares` lists the groups; each group's
 * `shares` names its members, one entry per member.
 *
 * Names are local metadata: they are not encoded into the mnemonics and do not
 * affect the cryptography.
 */
interface Slip39Json {
  /** Title for the whole set. */
  name?: string;
  /** How many groups are needed to reconstruct the master secret. */
  threshold?: number;
  shares: Array<{
    name?: string;
    /** How many of this group's members are needed. */
    threshold?: number;
    /** One name per member. Its length is the member count. */
    shares: string[];
  }>;
}

/** The result of `toJson({ mnemonics: true })`. */
interface Slip39JsonWithMnemonics {
  name: string;
  threshold: number;
  shares: Array<{
    name: string;
    threshold: number;
    shares: Array<{ name: string; mnemonic: string }>;
  }>;
}

interface Slip39JsonOptions {
  passphrase?: string;
  iterationExponent?: number;
  extendableBackupFlag?: number;
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
    threshold?: number,
  );

  index: number;
  description: string;
  mnemonic: string;
  children: Slip39Node[];
  /** For a group node, how many members are needed. 0 on leaves and the root. */
  threshold: number;

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

  /**
   * Splits a master secret according to a JSON description of the share tree.
   *
   * @param json The description, as an object or a JSON string.
   */
  static fromJson(
    masterSecret: number[],
    json: Slip39Json | string,
    options?: Slip39JsonOptions,
  ): Slip39;

  /** Validates a JSON description and converts it to `fromArray` groups. */
  static parseJson(json: Slip39Json | string): {
    title?: string;
    threshold: number;
    groups: Array<[number, number, string, string[]]>;
  };

  /**
   * Serialises the share tree back to the `fromJson` shape, so the result
   * round trips. Mnemonics are omitted unless asked for.
   */
  toJson(options?: { mnemonics?: false }): Slip39Json;
  /**
   * THE RESULT IS SECRET MATERIAL: it reconstructs the master secret. Do not
   * log it or write it out unencrypted.
   */
  toJson(options: { mnemonics: true }): Slip39JsonWithMnemonics;

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
  }
}
