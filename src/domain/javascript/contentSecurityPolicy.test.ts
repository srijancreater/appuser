import { describe, expect, it } from "vitest";

import { parseContentSecurityPolicy } from "./contentSecurityPolicy.js";

describe("Content-Security-Policy parsing", () => {
  it("rejects text whose directive names are not CSP directives", () => {
    expect(
      parseContentSecurityPolicy("color: red; margin-src 0", false),
    ).toBeUndefined();
    expect(parseContentSecurityPolicy("img-src 'self'", true)).toBeUndefined();
  });

  it("judges omissions only for fully static policies", () => {
    expect(
      parseContentSecurityPolicy("img-src 'self'; connect-src https:", false)
        ?.concerns,
    ).toEqual([
      expect.objectContaining({ directive: "connect-src", source: "https:" }),
      expect.objectContaining({ directive: "script-src", source: null }),
      expect.objectContaining({ directive: "object-src", source: null }),
    ]);
    expect(
      parseContentSecurityPolicy("img-src 'self'; connect-src ${…}", false)
        ?.concerns,
    ).toEqual([]);
  });

  it("ignores script 'unsafe-inline' when a nonce or hash is present", () => {
    expect(
      parseContentSecurityPolicy(
        "default-src 'self'; script-src 'nonce-abc' 'unsafe-inline'",
        false,
      )?.concerns,
    ).toEqual([]);
  });
});

it("judges only the first occurrence of each CSP directive", () => {
  expect(
    parseContentSecurityPolicy(
      "default-src 'none'; script-src 'none'; script-src *",
      false,
    )?.concerns,
  ).toEqual([]);
});
it.each(["attr", "elem"])(
  "retains the uncovered script use with only script-src-%s",
  (use) => {
    expect(
      parseContentSecurityPolicy(
        `script-src-${use} 'none'; object-src 'none'`,
        false,
      )?.concerns,
    ).toEqual([
      expect.objectContaining({
        directive: use === "attr" ? "script-src-elem" : "script-src-attr",
        source: null,
      }),
    ]);
  },
);
it("does not judge any source in a dynamic directive", () => {
  expect(
    parseContentSecurityPolicy(
      "script-src 'unsafe-inline' ${…}; object-src 'none'",
      false,
    )?.concerns,
  ).toEqual([]);
});
it("preserves known concerns beside unknown declared directives", () => {
  const policy = "script-src *; object-src 'none'; future-directive x";
  expect(parseContentSecurityPolicy(policy, false)?.concerns).toEqual([
    expect.objectContaining({ directive: "script-src", source: "*" }),
  ]);
  expect(parseContentSecurityPolicy(policy, true)).toBeUndefined();
});
