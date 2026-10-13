import { describe, expect, it } from "vitest";

import { analyzeJavaScriptStaticSource } from "./javascriptStaticAnalysis.js";

describe("native and CommonJS loader calls", () => {
  it("follows createRequire through an alias used as a parameter default", () => {
    const analysis = analyzeJavaScriptStaticSource(`
      var nodeModule = require("node:module");
      var load = (0, nodeModule.createRequire)(__import_meta_url);
      function addon(requireAddon = load) { return requireAddon("proclist"); }
      function unrelated(requireAddon = other) { return requireAddon("decoy"); }
      load("./direct.node");
    `);

    expect(
      analysis.references.filter(({ kind }) => kind === "require"),
    ).toMatchObject([{ specifier: "node:module" }, { specifier: "proclist" }]);
    expect(analysis.electron.native_addon_bindings).toMatchObject([
      {
        specifier: "./direct.node",
        binding_kind: "require",
        loader: "create-require",
        loader_basis: "alias",
      },
    ]);
  });
});
