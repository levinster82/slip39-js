const slipHelper = require("./slip39_helper.js");

const MAX_DEPTH = 2;

/**
 * Slip39Node
 * For root node, description refers to the whole set's title e.g. "Hardware wallet X SSSS shares"
 * For children nodes, description refers to the group e.g. "Family group: mom, dad, sister, wife"
 */
class Slip39Node {
  constructor(
    index = 0,
    description = "",
    mnemonic = "",
    children = [],
    threshold = 0,
  ) {
    this.index = index;
    this.description = description;
    this.mnemonic = mnemonic;
    this.children = children;
    // For a group node, how many of its members are needed. Recorded so the
    // tree can be serialised back out; 0 on leaves and on the root.
    this.threshold = threshold;
  }

  get mnemonics() {
    if (this.children.length === 0) {
      return [this.mnemonic];
    }
    const result = this.children.reduce((prev, item) => {
      return prev.concat(item.mnemonics);
    }, []);
    return result;
  }
}

//
// The javascript implementation of the SLIP-0039: Shamir's Secret-Sharing for Mnemonic Codes
// see: https://github.com/satoshilabs/slips/blob/master/slip-0039.md)
//
class Slip39 {
  constructor({
    iterationExponent = 0,
    extendableBackupFlag = 0,
    identifier,
    groupCount,
    groupThreshold,
  } = {}) {
    this.iterationExponent = iterationExponent;
    this.extendableBackupFlag = extendableBackupFlag;
    this.identifier = identifier;
    this.groupCount = groupCount;
    this.groupThreshold = groupThreshold;
  }

  static fromArray(
    masterSecret,
    {
      passphrase = "",
      threshold = 1,
      groups = [[1, 1, "Default 1-of-1 group share"]],
      iterationExponent = 0,
      extendableBackupFlag = 1,
      title = "My default slip39 shares",
    } = {},
  ) {
    if (masterSecret.length * 8 < slipHelper.MIN_ENTROPY_BITS) {
      throw Error(
        `The length of the master secret (${masterSecret.length} bytes) must be at least ${slipHelper.bitsToBytes(slipHelper.MIN_ENTROPY_BITS)} bytes.`,
      );
    }

    if (masterSecret.length % 2 !== 0) {
      throw Error(
        "The length of the master secret in bytes must be an even number.",
      );
    }

    // Note: SLIP-39 recommends, but does not require, restricting the
    // passphrase to printable ASCII (code points 32-126) for the widest
    // interoperability. Anything outside that range is encoded as NFKD UTF-8
    // per the spec, and may not be readable by other implementations.

    if (threshold > groups.length) {
      throw Error(
        `The requested group threshold (${threshold}) must not exceed the number of groups (${groups.length}).`,
      );
    }

    groups.forEach((item) => {
      if (item[0] === 1 && item[1] > 1) {
        throw Error(
          `Creating multiple member shares with member threshold 1 is not allowed. Use 1-of-1 member sharing instead. ${groups.join()}`,
        );
      }
    });

    const identifier = slipHelper.generateIdentifier();

    const slip = new Slip39({
      iterationExponent: iterationExponent,
      extendableBackupFlag: extendableBackupFlag,
      identifier: identifier,
      groupCount: groups.length,
      groupThreshold: threshold,
    });

    const encryptedMasterSecret = slipHelper.crypt(
      masterSecret,
      passphrase,
      iterationExponent,
      slip.identifier,
      extendableBackupFlag,
    );

    const root = slip.buildRecursive(
      new Slip39Node(0, title),
      groups,
      encryptedMasterSecret,
      threshold,
    );

    slip.root = root;
    return slip;
  }

  buildRecursive(currentNode, nodes, secret, threshold, index) {
    // It means it's a leaf.
    if (nodes.length === 0) {
      const mnemonic = slipHelper.encodeMnemonic(
        this.identifier,
        this.extendableBackupFlag,
        this.iterationExponent,
        index,
        this.groupThreshold,
        this.groupCount,
        currentNode.index,
        threshold,
        secret,
      );

      currentNode.mnemonic = mnemonic;
      return currentNode;
    }

    const secretShares = slipHelper.splitSecret(
      threshold,
      nodes.length,
      secret,
    );
    let children = [];
    let idx = 0;

    nodes.forEach((item) => {
      // n=threshold
      const n = item[0];
      // m=members
      const m = item[1];
      // d=description
      const d = item[2] || "";
      // names=per-member descriptions, supplied by fromJson. When absent every
      // member inherits the group's description, as it always has.
      const names = item[3];

      // Generate leaf members, means their `m` is `0`
      const members = slipHelper.generate(m, (i) => [
        n,
        0,
        names && names[i] ? names[i] : d,
      ]);

      const node = new Slip39Node(idx, d, "", [], n);
      const branch = this.buildRecursive(
        node,
        members,
        secretShares[idx],
        n,
        currentNode.index,
      );

      children = children.concat(branch);
      idx = idx + 1;
    });
    currentNode.children = children;
    return currentNode;
  }

  /**
   * Splits a master secret according to a JSON description of the share tree.
   *
   * The shape matches the one used by the sibling Dart implementation, so the
   * same configuration works in both:
   *
   *     {
   *       "name": "Alice's shares",
   *       "threshold": 2,
   *       "shares": [
   *         { "name": "Friends", "threshold": 3,
   *           "shares": ["Albert", "Ben", "Carol"] }
   *       ]
   *     }
   *
   * The outer `shares` lists the groups; each group's `shares` lists the names
   * of its members, one per member. Names are local metadata: they are not
   * encoded into the mnemonics and do not affect the cryptography.
   *
   * @param masterSecret Byte values, as for `fromArray`.
   * @param json The description above, either as an object or a JSON string.
   * @param options `passphrase`, `iterationExponent`, `extendableBackupFlag`.
   */
  static fromJson(masterSecret, json, options = {}) {
    const config = Slip39.parseJson(json);

    return Slip39.fromArray(masterSecret, {
      passphrase: options.passphrase,
      iterationExponent: options.iterationExponent,
      extendableBackupFlag: options.extendableBackupFlag,
      threshold: config.threshold,
      groups: config.groups,
      title: config.title,
    });
  }

  //
  // Validates a JSON share tree description and converts it to the group
  // tuples that `fromArray` understands.
  //
  static parseJson(json) {
    const data = typeof json === "string" ? JSON.parse(json) : json;

    if (data === null || typeof data !== "object" || Array.isArray(data)) {
      throw new Error(
        `Expected a JSON object describing the shares. Instead found ${Array.isArray(data) ? "an array" : `typeof ${typeof data}`}.`,
      );
    }

    if (!Array.isArray(data.shares)) {
      throw new Error(
        'The JSON must have a "shares" array listing the groups.',
      );
    }

    const groups = data.shares.map((group, index) => {
      if (group === null || typeof group !== "object" || Array.isArray(group)) {
        throw new Error(
          `Group ${index} must be an object with "name", "threshold" and "shares".`,
        );
      }

      if (!Array.isArray(group.shares) || group.shares.length === 0) {
        throw new Error(
          `Group ${index} ("${group.name || ""}") must have a non-empty "shares" array naming its members.`,
        );
      }

      const names = group.shares.map((member, memberIndex) => {
        if (typeof member !== "string") {
          throw new Error(
            `Member ${memberIndex} of group ${index} ("${group.name || ""}") must be a string naming the share. Instead found typeof ${typeof member}.`,
          );
        }
        return member;
      });

      const threshold =
        typeof group.threshold === "undefined" ? 1 : group.threshold;

      return [threshold, names.length, group.name || "", names];
    });

    return {
      title: data.name,
      threshold: typeof data.threshold === "undefined" ? 1 : data.threshold,
      groups: groups,
    };
  }

  /**
   * Serialises the share tree back to the `fromJson` shape.
   *
   * With no arguments the result round trips: feeding it back to `fromJson`
   * reproduces the same structure. Mnemonics are omitted by default so that
   * logging or stringifying a Slip39 cannot leak secrets by accident.
   *
   * @param options Pass `{ mnemonics: true }` to include the generated
   *   mnemonics. THE RESULT IS THEN SECRET MATERIAL: it reconstructs the
   *   master secret, so do not log it or write it out unencrypted.
   */
  toJson({ mnemonics = false } = {}) {
    return {
      name: this.root.description,
      threshold: this.groupThreshold,
      shares: this.root.children.map((group) => {
        return {
          name: group.description,
          threshold: group.threshold,
          shares: group.children.map((member) => {
            return mnemonics
              ? { name: member.description, mnemonic: member.mnemonic }
              : member.description;
          }),
        };
      }),
    };
  }

  static recoverSecret(mnemonics, passphrase) {
    return slipHelper.combineMnemonics(mnemonics, passphrase);
  }

  static validateMnemonic(mnemonic) {
    return slipHelper.validateMnemonic(mnemonic);
  }

  fromPath(path) {
    this.validatePath(path);

    const children = this.parseChildren(path);

    if (typeof children === "undefined" || children.length === 0) {
      return this.root;
    }

    return children.reduce((prev, childNumber) => {
      let childrenLen = prev.children.length;
      if (childNumber >= childrenLen) {
        throw new Error(
          `The path index (${childNumber}) exceeds the children index (${childrenLen - 1}).`,
        );
      }

      return prev.children[childNumber];
    }, this.root);
  }

  validatePath(path) {
    if (!path.match(/(^r)(\/\d{1,2}){0,2}$/)) {
      throw new Error('Expected valid path e.g. "r/0/0".');
    }

    const depth = path.split("/");
    const pathLength = depth.length - 1;
    if (pathLength > MAX_DEPTH) {
      throw new Error(
        `Path's (${path}) max depth (${MAX_DEPTH}) is exceeded (${pathLength}).`,
      );
    }
  }

  parseChildren(path) {
    const splitted = path.split("/").slice(1);

    const result = splitted.map((pathFragment) => {
      return parseInt(pathFragment);
    });
    return result;
  }
}

exports = module.exports = Slip39;
