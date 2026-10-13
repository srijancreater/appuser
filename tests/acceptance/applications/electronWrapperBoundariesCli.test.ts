import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { expect } from "vitest";
import { z } from "zod";

import { javascriptApplicationAnalysisResultSchema } from "../../../src/domain/javascript/javascriptApplicationAnalysis.js";
import { connectLocalToolsMcp } from "../../fixtures/localToolsMcp.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { cliTest, type TestCli } from "../../support/cli/cliFixture.js";

const MAIN = `const electron = require("electron");
function registerSnapshot(deps) {
  deps.ipcMain.on("app:snapshot", (event) => { event.returnValue = 1; });
}
registerSnapshot({ ipcMain: electron.ipcMain, store: {} });
function transport(ipc, facts) {
  return { handle: (channel, run) => ipc.handle(channel, (event, arg) => run(facts(event), arg)) };
}
transport(electron.ipcMain, () => ({}));
transport(options.ipcMain, () => ({}));
function consent(request, Window) {
  return new Window({ webPreferences: { nodeIntegration: false, contextIsolation: true } });
}
consent({}, injected.BrowserWindow ?? electron.BrowserWindow);
const path = require("node:path");
const avatar = new electron.WebContentsView({ webPreferences: { sandbox: !0, preload: path.join(__dirname, "preload.cjs") } });
function harden(contents) {
  contents.on("will-attach-webview", (event, prefs, params) => {
    prefs.nodeIntegration = !1, prefs.contextIsolation = !0, prefs.sandbox = !0;
    prefs.preload = path.join(__dirname, "webview-preload.cjs");
    if (!params.src.startsWith("https:")) delete params.src;
  });
}
const dialogs = injected.electron ?? { BrowserWindow: electron.BrowserWindow };
new dialogs.BrowserWindow({ show: false });
const { createRequire } = require("node:module");
const load = createRequire(__filename);
function proclist(requireAddon = load) { return requireAddon("proclist"); }
load("./native/direct.node");
process.dlopen(module, path.join(__dirname, "native", "direct.node"));
require("gyp");
session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
  callback({ responseHeaders: { ...details.responseHeaders, "Content-Security-Policy": ["default-src 'self'; script-src 'self' 'unsafe-eval'; img-src * data:"] } });
});
const framePolicy = (extra) => ["default-src 'none'", \`script-src 'self' \${extra}\`, "object-src 'none'"].join("; ");
throw new Error("must not execute main");
`;

const PRELOAD = `const { contextBridge, ipcRenderer } = require("electron");
function expose(bridge) { bridge.exposeInMainWorld("reliability", { report: 1 }); }
expose(contextBridge);
ipcRenderer.sendSync("app:snapshot");
const update = { check() {}, quitAndInstall: () => 0 };
const desktop = { openExternal() {}, update, theme: { get: 1 }, ...(cookies == null ? {} : { chromeCookies: cookies }) };
contextBridge.exposeInMainWorld("desktop", desktop);
const patched = { ready: 1 };
patched.late = 2;
contextBridge.exposeInMainWorld("patched", patched);
throw new Error("must not execute preload");
`;

// ELF magic only; native files are inventoried, never loaded.
const NATIVE = Buffer.from([0x7f, 0x45, 0x4c, 0x46]);

type Graph = z.infer<typeof javascriptApplicationAnalysisResultSchema>["graph"];

const located = (graph: Graph, kind: string, line: number) =>
  graph.nodes.find(
    (node) =>
      node.kind === kind &&
      node.observations.some(({ evidence: { location } }) =>
        location.available && location.value.kind === "source-range"
          ? location.value.start.line === line
          : false,
      ),
  );

const analyze = async (
  surface: "CLI" | "stdio MCP",
  cli: TestCli,
  root: string,
) => {
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
  return z
    .object({ normalized_result: javascriptApplicationAnalysisResultSchema })
    .parse(document).normalized_result;
};

const expectWrapperIdentities = (graph: Graph): void => {
  const snapshot = located(graph, "ipc-handler", 3);
  expect(snapshot?.observations[0]?.properties).toMatchObject({
    channel: "app:snapshot",
    electron_identity: {
      basis: "wrapper-parameter",
      function_name: "registerSnapshot",
      parameter: "deps",
      call_sites: 1,
      call_sites_complete: true,
      electron_argument_locations: [
        { start: { line: 5, column: 28 }, end: { line: 5, column: 44 } },
      ],
      unresolved_arguments: 0,
    },
  });
  expect(
    graph.edges.find(
      ({ relation, target_node_id: target }) =>
        relation === "contains" && target === snapshot?.node_id,
    )?.evidence,
  ).toMatchObject({ state: "inferred", confidence: "medium" });

  const transported = located(graph, "ipc-handler", 7);
  expect(transported?.observations[0]?.properties).toMatchObject({
    channel: null,
    channel_expression: "channel",
    electron_identity: {
      function_name: "transport",
      unresolved_arguments: 1,
    },
  });
  expect(
    graph.edges.find(
      ({ relation, target_node_id: target }) =>
        relation === "contains" && target === transported?.node_id,
    )?.evidence,
  ).toMatchObject({ state: "inferred", confidence: "low" });

  expect(located(graph, "browser-window", 12)?.observations[0]).toMatchObject({
    properties: {
      electron_identity: {
        function_name: "consent",
        parameter: "Window",
        parameter_index: 1,
        unresolved_arguments: 1,
      },
    },
    evidence: { state: "observed" },
  });
};

const expectWindowsAndWebviews = (graph: Graph): void => {
  expect(
    located(graph, "web-contents-view", 16)?.observations[0]?.properties,
  ).toMatchObject({
    api: "WebContentsView",
    web_preferences: expect.arrayContaining([
      {
        name: "sandbox",
        value: { status: "derived", value: true, expression: "!0" },
      },
    ]),
    preload_path: "preload.cjs",
  });
  const attach = graph.nodes
    .flatMap(({ observations }) => observations)
    .find(
      ({ properties }) => properties.fact_kind === "webview-attach-handler",
    );
  expect(attach?.properties).toMatchObject({
    handler_kind: "inline-function",
    preload_path: "webview-preload.cjs",
    preload_resolution_context: "filesystem-expression",
    unknown_writes: 0,
    writes: [
      {
        target: "web-preferences",
        name: "nodeIntegration",
        operation: "assign",
        value: { value: false },
      },
      {
        target: "web-preferences",
        name: "contextIsolation",
        operation: "assign",
        value: { value: true },
      },
      {
        target: "web-preferences",
        name: "sandbox",
        operation: "assign",
        value: { value: true },
      },
      {
        target: "web-preferences",
        name: "preload",
        operation: "assign",
        value: { value: "webview-preload.cjs" },
      },
      { target: "params", name: "src", operation: "delete", value: null },
    ],
  });
  expect(
    graph.nodes.some(
      ({ kind, observations }) =>
        kind === "electron-preload" &&
        observations.some(
          ({ properties }) =>
            properties.mechanism ===
            "will-attach-webview:webPreferences.preload",
        ),
    ),
  ).toBe(true);
};

const expectLocalAlternatives = (graph: Graph): void => {
  expect(
    located(graph, "browser-window", 25)?.observations[0]?.properties,
  ).toMatchObject({
    electron_identity: {
      basis: "local-alternatives",
      binding: "dialogs",
      unresolved_values: 1,
    },
  });
};

const expectNativeLoaders = (graph: Graph): void => {
  const bindings = graph.nodes.flatMap(({ kind, observations }) =>
    kind === "native-export"
      ? observations.map(({ properties }) => properties)
      : [],
  );
  expect(bindings).toEqual(
    expect.arrayContaining([
      expect.objectContaining({
        specifier: "./native/direct.node",
        loader: "create-require",
        loader_basis: "alias",
        resolved_path: "native/direct.node",
      }),
      expect.objectContaining({
        binding_kind: "loader",
        loader: "process-dlopen",
        specifier: "native/direct.node",
        resolved_path: "native/direct.node",
      }),
      expect.objectContaining({
        binding_kind: "loader",
        loader: "node-gyp-build",
        resolution_basis: "loader-package-root",
        resolved_path: "node_modules/gyp/build/Release/gyp.node",
        candidate_paths: ["node_modules/gyp/build/Release/gyp.node"],
      }),
    ]),
  );
};

const expectPolicies = (graph: Graph): void => {
  const policies = graph.nodes.flatMap(({ observations }) =>
    observations.flatMap(({ properties, evidence }) =>
      properties.fact_kind === "content-security-policy"
        ? [{ properties, evidence }]
        : [],
    ),
  );
  expect(policies.map(({ properties }) => properties)).toEqual(
    expect.arrayContaining([
      expect.objectContaining({
        mechanism: "header-property",
        header: "content-security-policy",
        concerns: [
          {
            directive: "script-src",
            source: "'unsafe-eval'",
            reason: "'unsafe-eval' allows string evaluation.",
          },
          {
            directive: "img-src",
            source: "*",
            reason: "The wildcard source allows any host.",
          },
        ],
      }),
      expect.objectContaining({
        mechanism: "directive-list",
        policy: "default-src 'none'; script-src 'self' ${…}; object-src 'none'",
        dynamic_parts: 1,
        concerns: [],
      }),
      expect.objectContaining({
        mechanism: "html-meta",
        directives: [
          { name: "default-src", sources: ["'self'"] },
          { name: "style-src", sources: ["'self'", "'unsafe-inline'"] },
          { name: "connect-src", sources: ["'self'", "ws:"] },
        ],
        concerns: [
          expect.objectContaining({
            directive: "style-src",
            source: "'unsafe-inline'",
          }),
          expect.objectContaining({ directive: "connect-src", source: "ws:" }),
        ],
      }),
    ]),
  );
};

const expectBridgeObjects = (graph: Graph): void => {
  expect(
    located(graph, "context-bridge-api", 2)?.observations[0]?.properties,
  ).toMatchObject({
    api_key: "reliability",
    members: ["report"],
    electron_identity: { function_name: "expose", parameter: "bridge" },
  });
  expect(
    located(graph, "context-bridge-api", 7)?.observations[0]?.properties,
  ).toMatchObject({
    api_key: "desktop",
    api_status: "object-binding",
    members: [
      "openExternal",
      "theme",
      "theme.get",
      "update",
      "update.check",
      "update.quitAndInstall",
    ],
    conditional_members: ["chromeCookies"],
    unknown_members: 0,
  });
  expect(
    located(graph, "context-bridge-api", 10)?.observations[0]?.properties,
  ).toMatchObject({
    api_key: "patched",
    api_status: "object-binding",
    members: ["ready"],
    unknown_members: 1,
  });
};

cliTest.for(["CLI", "stdio MCP"] as const)(
  "maps Electron wrappers, bridge objects, views and webview hardening through %s without executing source",
  async (surface, { cli }) => {
    const root = await createTestTempDirectory("rea-electron-wrappers-");
    await Promise.all([
      writeFile(
        join(root, "package.json"),
        JSON.stringify({ main: "main.cjs" }),
      ),
      writeFile(join(root, "main.cjs"), MAIN),
      writeFile(join(root, "preload.cjs"), PRELOAD),
      writeFile(
        join(root, "index.html"),
        `<!doctype html><meta http-equiv="Content-Security-Policy" content="default-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' ws:">`,
      ),
      writeFile(
        join(root, "webview-preload.cjs"),
        'throw new Error("inert preload");\n',
      ),
      mkdir(join(root, "native")).then(() =>
        writeFile(join(root, "native", "direct.node"), NATIVE),
      ),
      mkdir(join(root, "node_modules", "gyp", "build", "Release"), {
        recursive: true,
      }).then(() =>
        Promise.all([
          writeFile(
            join(root, "node_modules", "gyp", "package.json"),
            JSON.stringify({ name: "gyp", main: "index.js" }),
          ),
          writeFile(
            join(root, "node_modules", "gyp", "index.js"),
            'module.exports = require("node-gyp-build")(__dirname);\n',
          ),
          writeFile(
            join(root, "node_modules", "gyp", "build", "Release", "gyp.node"),
            NATIVE,
          ),
        ]),
      ),
    ]);

    const { graph, summary } = await analyze(surface, cli, root);

    expect(summary).toMatchObject({
      browser_windows: 2,
      web_contents_views: 1,
      webview_attach_handlers: 1,
      preload_entrypoints: 2,
      inferred_api_identity_findings: 5,
      content_security_policies: 3,
      content_security_policy_concerns: 4,
      context_bridge_apis: 3,
      ipc: { main_handlers: 2, paired_renderer_transmissions: 1 },
    });
    expectWrapperIdentities(graph);
    expectWindowsAndWebviews(graph);
    expectBridgeObjects(graph);
    expectLocalAlternatives(graph);
    expectNativeLoaders(graph);
    expectPolicies(graph);
  },
);
