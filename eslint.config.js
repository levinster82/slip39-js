const js = require("@eslint/js");

//
// Replaces the legacy .eslintrc.js, which was never runnable: eslint was not a
// devDependency and no lint script existed. The rule set below keeps the
// intent of that file - correctness rules as errors, style left to Prettier -
// expressed as flat config.
//
module.exports = [
  js.configs.recommended,
  {
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "commonjs",
      globals: {
        require: "readonly",
        module: "writable",
        exports: "writable",
        process: "readonly",
        console: "readonly",
        Buffer: "readonly",
        BigInt: "readonly",
        __dirname: "readonly",
      },
    },
    rules: {
      "no-unused-vars": ["error", { args: "none" }],
      "no-var": "error",
      eqeqeq: ["error", "always"],
      "no-extend-native": "off", // see the compat shims in src/slip39_helper.js
    },
  },
  {
    files: ["test/**/*.js"],
    languageOptions: {
      globals: {
        describe: "readonly",
        it: "readonly",
        before: "readonly",
        after: "readonly",
        beforeEach: "readonly",
        afterEach: "readonly",
      },
    },
  },
];
