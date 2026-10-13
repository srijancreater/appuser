import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import { expect } from "vitest";
import { z } from "zod";

import { javascriptApplicationAnalysisResultSchema } from "../../../src/domain/javascript/javascriptApplicationAnalysis.js";
import { connectLocalToolsMcp } from "../../fixtures/localToolsMcp.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { cliTest } from "../../support/cli/cliFixture.js";

const MAIN = `
const { BrowserWindow, ipcMain } = require("electron");
var PREFIX = "sand:";
const ALIVE = PREFIX + "renderer-alive";
new BrowserWindow({ webPreferences: {
  contextIsolation: !0, sandbox: !1, nodeIntegration: void 0, webviewTag: runtimeFlag,
} });
ipcMain.on(ALIVE, () => {});
ipcMain.handle(\`\${PREFIX}ping\`, () => {});
const base = "https://api." + "example.invalid";
fetch(base + "/v1/" + String.fromCharCode(109, 101));
fetch(runtimeBase + "/v1/unknown");
`;

const PRELOAD = `
const { contextBridge, ipcRenderer } = require("electron");
var PREFIX = "sand:";
ipcRenderer.send(PREFIX + "renderer-alive");
ipcRenderer.invoke(\`\${PREFIX}ping\`);
contextBridge.exposeInMainWorld(["de", "sktop"].join(""), { ping: () => 1 });
`;

cliTest.for(["CLI", "stdio MCP"] as const)(
  "reports values folded from constant expressions through %s",
  async (surface, { cli }) => {
    const root = await createTestTempDirectory("rea-constant-folding-");
    await Promise.all([
      writeFile(join(root, "main.js"), MAIN),
      writeFile(join(root, "preload.js"), PRELOAD),
    ]);

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
    const { graph, summary } = z
      .object({ normalized_result: javascriptApplicationAnalysisResultSchema })
      .parse(document).normalized_result;
    const propertiesOf = (kind: string) =>
      graph.nodes
        .filter((node) => node.kind === kind)
        .flatMap(({ observations }) =>
          observations.map(({ properties }) => properties),
        );

    expect(propertiesOf("browser-window")).toEqual([
      expect.objectContaining({
        web_preferences: [
          {
            name: "contextIsolation",
            value: { status: "derived", value: true, expression: "!0" },
          },
          {
            name: "nodeIntegration",
            value: { status: "dynamic", value: null, expression: "void 0" },
          },
          {
            name: "sandbox",
            value: { status: "derived", value: false, expression: "!1" },
          },
          {
            name: "webviewTag",
            value: {
              status: "dynamic",
              value: null,
              expression: "runtimeFlag",
            },
          },
        ],
      }),
    ]);
    expect(summary.ipc).toMatchObject({
      operations: 4,
      literal_channels: 2,
      dynamic_channel_operations: 0,
      paired_renderer_transmissions: 2,
    });
    expect(propertiesOf("ipc-channel")).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          channel: "sand:renderer-alive",
          channel_expression: 'PREFIX + "renderer-alive"',
          resolution: "derived",
        }),
        expect.objectContaining({
          channel: "sand:ping",
          channel_expression: "`${PREFIX}ping`",
          resolution: "derived",
        }),
      ]),
    );
    expect(
      graph.edges
        .filter(
          ({ evidence }) =>
            evidence.extractor.operation === "pair-ipc-literal-channel",
        )
        .map(({ properties }) => properties.pairing_basis),
    ).toEqual(["unique-exact-derived-channel", "unique-exact-derived-channel"]);
    expect(propertiesOf("context-bridge-api")).toEqual([
      expect.objectContaining({
        api_key: "desktop",
        api_key_expression: '["de", "sktop"].join("")',
      }),
    ]);
    const network = graph.nodes.filter(
      ({ kind, observations }) =>
        kind === "endpoint" &&
        observations.some(
          ({ properties }) => properties.endpoint_kind === "network",
        ),
    );
    expect(network.flatMap(({ observations }) => observations)).toEqual([
      expect.objectContaining({
        properties: {
          endpoint_kind: "network",
          value: "https://api.example.invalid/v1/me",
          expression: 'base + "/v1/" + String.fromCharCode(109, 101)',
          mechanism: "call:fetch",
          url_class: "http",
          host: "api.example.invalid",
          property_path: null,
        },
        evidence: expect.objectContaining({
          limitations: expect.arrayContaining([
            expect.stringMatching(/folded from a constant expression/u),
          ]),
        }),
      }),
    ]);
  },
);
