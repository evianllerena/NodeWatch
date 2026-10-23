// Lint for NodeWatch frontend scripts: catches calls to functions that do not exist
// (the v0.10.6 formatBytes crash) and other undefined references.
// Run: eslint app/static   (tests/test_frontend_js.py runs it when eslint is installed)
module.exports = [
  {
    files: ["app/static/**/*.js"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "script",
      globals: {
        window: "readonly", document: "readonly", console: "readonly", fetch: "readonly",
        setTimeout: "readonly", setInterval: "readonly", clearTimeout: "readonly", clearInterval: "readonly",
        URL: "readonly", URLSearchParams: "readonly", Headers: "readonly", Request: "readonly",
        performance: "readonly", location: "readonly", history: "readonly", alert: "readonly",
        confirm: "readonly", prompt: "readonly", Blob: "readonly", navigator: "readonly",
        requestAnimationFrame: "readonly", localStorage: "readonly", sessionStorage: "readonly",
        HTMLElement: "readonly", Event: "readonly", CustomEvent: "readonly", getComputedStyle: "readonly",
        Notification: "readonly", structuredClone: "readonly",
        MutationObserver: "readonly", HTMLSelectElement: "readonly", WeakMap: "readonly",
      },
    },
    rules: {
      "no-undef": "error",
      "no-unused-vars": ["warn", { args: "none" }],
      "no-redeclare": "error",
      "no-dupe-keys": "error",
      "no-unreachable": "error",
    },
  },
  {
    // core.js defines getJSON as a global; index.html loads it before every module.
    files: ["app/static/modules/**/*.js"],
    languageOptions: { globals: { getJSON: "readonly" } },
  },
];
