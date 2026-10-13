import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import { expect } from "vitest";
import { z } from "zod";

import { javascriptApplicationAnalysisResultSchema } from "../../../src/domain/javascript/javascriptApplicationAnalysis.js";
import { connectLocalToolsMcp } from "../../fixtures/localToolsMcp.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { cliTest } from "../../support/cli/cliFixture.js";

const MAIN = `
const PROVIDERS = new Map([["api.x.com", { provider: "x" }]]);
class Voice { static DIALABLE_ORIGIN = "wss://api.x.ai/"; }
const config = {
  api: { base: "https://api." + "example.invalid" },
  icons: ["/assets/a.png"],
  pixel: "data:image/png;base64,AAAA",
};
fetch("https://used.example.invalid/v1");
const scope = "team.billing.read";
const readme = "README.md";
`;

cliTest.for(["CLI", "stdio MCP"] as const)(
  "reports URL, host, and path values present in data through %s",
  async (surface, { cli }) => {
    const root = await createTestTempDirectory("rea-data-endpoints-");
    await writeFile(join(root, "main.js"), MAIN);

    let document: unknown;
    if (surface === "CLI") {
      const response = await cli.run({
        arguments: ["analyze-javascript-application", root, "--format", "json"],
        environment: { REA_LOG_LEVEL: "silent" },
      });
      expect(response.exitCode, response.stderr).toBe(0);
      document = response.json;
    } else {
      const { call } = await connectLocalToolsMcp();
      const response = await call("analyze_javascript_application", {
        input_path: root,
      });
      expect(response.isError, JSON.stringify(response)).not.toBe(true);
      document = response.structuredContent;
    }
    const { graph } = z
      .object({ normalized_result: javascriptApplicationAnalysisResultSchema })
      .parse(document).normalized_result;
    const endpoints = graph.nodes.flatMap(({ kind, observations }) =>
      kind === "endpoint"
        ? observations.map(({ properties }) => properties)
        : [],
    );

    expect(endpoints).toEqual(
      expect.arrayContaining([
        {
          endpoint_kind: "data",
          value: "api.x.com",
          expression: null,
          mechanism: "string-literal",
          url_class: "host",
          host: "api.x.com",
          property_path: ["PROVIDERS", "Map()", "0", "0", "0"],
        },
        {
          endpoint_kind: "data",
          value: "wss://api.x.ai/",
          expression: null,
          mechanism: "string-literal",
          url_class: "websocket",
          host: "api.x.ai",
          property_path: ["Voice", "DIALABLE_ORIGIN"],
        },
        {
          endpoint_kind: "data",
          value: "https://api.example.invalid",
          expression: '"https://api." + "example.invalid"',
          mechanism: "folded-expression",
          url_class: "http",
          host: "api.example.invalid",
          property_path: ["config", "api", "base"],
        },
        {
          endpoint_kind: "data",
          value: "/assets/a.png",
          expression: null,
          mechanism: "string-literal",
          url_class: "path",
          host: null,
          property_path: ["config", "icons", "0"],
        },
        {
          endpoint_kind: "data",
          value: "data:image/png;base64,AAAA",
          expression: null,
          mechanism: "string-literal",
          url_class: "data",
          host: null,
          property_path: ["config", "pixel"],
        },
        {
          endpoint_kind: "network",
          value: "https://used.example.invalid/v1",
          expression: null,
          mechanism: "call:fetch",
          url_class: "http",
          host: "used.example.invalid",
          property_path: null,
        },
      ]),
    );
    expect(endpoints).toHaveLength(6);
    const edges = graph.edges.filter(
      ({ evidence }) =>
        evidence.extractor.operation === "locate-data-endpoint-value",
    );
    expect(edges).toHaveLength(5);
    expect(edges.every(({ relation }) => relation === "contains")).toBe(true);
  },
);
