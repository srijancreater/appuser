import { expect, it } from "vitest";

import { analyzeJavaScriptSemantics } from "./javascriptSemanticAnalysis.js";
import { topLevelBinding } from "./javascriptSemanticAnalysis.fixture.js";

it.each([
  { expression: "!0", value: true },
  { expression: "!1", value: false },
  { expression: "!void 0", value: true },
  { expression: "typeof void 0", value: "undefined" },
  { expression: '"a" + void 0', value: "aundefined" },
  { expression: '"a" + void runtimeValue()', value: "aundefined" },
  { expression: '"" + 1 / 0', value: "Infinity" },
  { expression: "-1 / 0 < 0", value: true },
  { expression: "2 ** 10 | 1", value: 1025 },
  { expression: '"a" + "b" === "ab"', value: true },
  { expression: "`wss://${host}/v${2 + 1}`", value: "wss://api.example/v3" },
  { expression: "`${void 0}:${-1 / 0}`", value: "undefined:-Infinity" },
  { expression: '["ap", "i.", "example"].join("")', value: "api.example" },
  { expression: "[1, , null, void 0, 2].join()", value: "1,,,,2" },
  { expression: "String.fromCharCode(104, 105)", value: "hi" },
])("folds $expression into an exact primitive", ({ expression, value }) => {
  const ir = analyzeJavaScriptSemantics(
    `const host = "api.example"; const value = ${expression};`,
  );
  expect(topLevelBinding(ir, "value").value).toEqual({
    status: "literal",
    value,
  });
});

it("folds identifiers bound once, including never-reassigned var bindings", () => {
  const ir = analyzeJavaScriptSemantics(
    'var prefix = "sand:"; const channel = prefix + "renderer-" + (!0 + "");',
  );
  expect(topLevelBinding(ir, "channel").value).toEqual({
    status: "literal",
    value: "sand:renderer-true",
  });
});

it.each([
  {
    expression: "void 0",
    reason: "undefined is outside the JSON primitive lattice.",
  },
  {
    expression: "1 / 0",
    reason: "Nonfinite numbers are outside the JSON primitive lattice.",
  },
  { expression: 'unknownValue || "fallback"', reason: undefined },
  { expression: "String.fromCharCode(code)", reason: undefined },
  { expression: '[part, "x"].join("")', reason: undefined },
  { expression: "items.join()", reason: undefined },
  { expression: 'reassigned + "x"', reason: undefined },
])("keeps $expression unknown", ({ expression, reason }) => {
  const ir = analyzeJavaScriptSemantics(
    `var reassigned = "a"; reassigned = "b"; const value = ${expression};`,
  );
  const value = topLevelBinding(ir, "value").value;
  expect(value.status).not.toBe("literal");
  if (reason !== undefined) expect(value).toMatchObject({ reason });
});

it("keeps shadowed intrinsics and globals unknown", () => {
  const ir = analyzeJavaScriptSemantics(
    'const String = { fromCharCode: () => "x" }; const Infinity = 1; const a = String.fromCharCode(104); const b = "" + Infinity;',
  );
  expect(topLevelBinding(ir, "a").value.status).toBe("unknown");
  expect(topLevelBinding(ir, "b").value).toEqual({
    status: "literal",
    value: "1",
  });
});

it("folds request endpoints and configuration defaults", () => {
  const ir = analyzeJavaScriptSemantics(`
    const base = "https://api." + "example.invalid";
    const mode = process.env.MODE ?? ["pro", "duction"].join("");
    const empty = process.env.EMPTY ?? null;
    fetch(base + "/v1/" + String.fromCharCode(109, 101));
    fetch(runtimeBase + "/v1");
  `);
  expect(
    ir.requestOperations.map(({ endpoint, resolution }) => ({
      endpoint,
      resolution,
    })),
  ).toEqual([
    { endpoint: "https://api.example.invalid/v1/me", resolution: "complete" },
    { endpoint: null, resolution: "partial" },
  ]);
  expect(
    ir.configurationOperations.flatMap(({ kind, value, resolution }) =>
      kind === "default" ? [{ value, resolution }] : [],
    ),
  ).toEqual([
    { value: "production", resolution: "complete" },
    { value: null, resolution: "complete" },
  ]);
});
