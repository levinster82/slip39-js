const slip39 = require("../src/slip39.js");
const assert = require("assert");

const masterSecret = "ABCDEFGHIJKLMNOP".slip39EncodeHex();
const passphrase = "TREZOR";

/**
 * The same 2-of-4 group scheme as `main.js`, described as JSON instead of as
 * an array of tuples.
 *
 * What the JSON form adds is a name for every individual share, so you can
 * keep track of who is holding what. The outer `shares` lists the groups; each
 * group's `shares` names its members, one entry per member, so its length is
 * the member count.
 *
 * Names are local metadata only. They are not encoded into the mnemonics and
 * have no effect on the cryptography, so two shares are interchangeable
 * regardless of whose name is attached.
 */
const config = {
  name: "Slip39 example for 2-level SSSS",
  threshold: 2,
  shares: [
    { name: "Alice personal 1", threshold: 1, shares: ["Alice's safe"] },
    { name: "Alice personal 2", threshold: 1, shares: ["Alice's deposit box"] },
    {
      name: "Friends",
      threshold: 3,
      shares: ["Bob", "Charlie", "Dave", "Frank", "Grace"],
    },
    {
      name: "Family",
      threshold: 2,
      shares: ["mom", "dad", "brother", "sister", "wife", "cousin"],
    },
  ],
};

// `fromJson` also accepts the description as a JSON string, e.g. one read
// straight off disk with fs.readFileSync().
const slip = slip39.fromJson(masterSecret, config, {
  passphrase: passphrase,
});

/*
 * Every share knows who holds it.
 */
console.log("\n* Who holds which share:");
slip.root.children.forEach((group) => {
  console.log(
    `\n\t${group.description} (any ${group.threshold} of ${group.children.length}):`,
  );
  group.children.forEach((member) => {
    const firstWords = member.mnemonic.split(" ").slice(0, 4).join(" ");
    console.log(`\t\t${member.description.padEnd(20)} ${firstWords} ...`);
  });
});

// The names are on the nodes, so a path lookup reports the holder.
assert.strictEqual(slip.fromPath("r/2/0").description, "Bob");
assert.strictEqual(slip.fromPath("r/3/4").description, "wife");

/*
 * Recovering by name rather than by path.
 *
 * Passing { mnemonics: true } returns the tree with each share's mnemonic
 * alongside its name, which makes it easy to pick out named holders.
 */
const withMnemonics = slip.toJson({ mnemonics: true });

function mnemonicFor(holder) {
  const found = withMnemonics.shares
    .reduce((all, group) => all.concat(group.shares), [])
    .find((share) => share.name === holder);

  assert(found, `No share is held by ${holder}.`);
  return found.mnemonic;
}

// Alice's deposit box reconstructs one group share on its own, and any three
// friends reconstruct another. Two group shares is the threshold.
const holders = ["Alice's deposit box", "Bob", "Charlie", "Dave"];
const shares = holders.map(mnemonicFor);

console.log(`\n* Restoring from: ${holders.join(", ")}`);

const recovered = slip39.recoverSecret(shares, passphrase);
console.log("\tMaster secret: " + masterSecret.slip39DecodeHex());
console.log("\tRecovered one: " + recovered.slip39DecodeHex());
assert(masterSecret.slip39DecodeHex() === recovered.slip39DecodeHex());

/*
 * Serialising back out.
 *
 * toJson() omits the mnemonics, so it is safe to log, and returns exactly the
 * shape fromJson accepts. That makes it a lossless round trip: the output can
 * be stored as the record of who should hold what, and fed back in later.
 */
const roundTripped = slip.toJson();

console.log("\n* toJson() round trips the configuration:");
console.log("\t" + JSON.stringify(roundTripped.shares[2]));
assert.deepStrictEqual(roundTripped, config);

// Nothing secret escapes unless you ask for it.
const serialised = JSON.stringify(roundTripped);
slip.fromPath("r").mnemonics.forEach((mnemonic) => {
  assert(!serialised.includes(mnemonic));
});
console.log("\tand contains no mnemonics.");

/*
 * WARNING: the output of toJson({ mnemonics: true }), used above to look up
 * holders, reconstructs the master secret. Treat it as secret material: do not
 * log it, and do not write it to disk unencrypted.
 */
