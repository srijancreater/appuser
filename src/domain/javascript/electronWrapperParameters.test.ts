import { describe, expect, it } from "vitest";

import { analyzeJavaScriptStaticSource } from "./javascriptStaticAnalysis.js";

describe("Electron API identity through wrapper parameters", () => {
  it("infers Electron APIs passed through one wrapper parameter with provenance", () => {
    const analysis = analyzeJavaScriptStaticSource(`
      const electron = require("electron");
      function registerSnapshot(deps) {
        deps.ipcMain.on("snapshot", (event) => { event.returnValue = 1; });
      }
      registerSnapshot({ ipcMain: electron.ipcMain, store: {} });
      function transport(ipc, facts) {
        return { handle: (channel, run) => ipc.handle(channel, (event, arg) => run(facts(event), arg)) };
      }
      transport(electron.ipcMain, () => ({}));
      transport(options.ipcMain, () => ({}));
      async function consent(request, Window) {
        return new Window({ webPreferences: { contextIsolation: true } });
      }
      consent({}, injected.BrowserWindow ?? electron.BrowserWindow);
      const expose = ({ contextBridge: bridge }) => bridge.exposeInMainWorld("api", { ping: 1 });
      expose(electron);
      function ambiguous(target) { new target.Thing(); target.handle("x", () => 0); }
      ambiguous(electron.ipcMain);
      ambiguous(electron.BrowserWindow);
      function unused(electron) { new electron.BrowserWindow({}); }
      function escaped(ipc) { ipc.handle("escaped", () => 0); }
      escaped(electron.ipcMain);
      callbacks.push(escaped);
    `);

    expect(
      analysis.electron.ipc.map(
        ({ operation, channel, channel_expression, electron_identity }) => ({
          operation,
          channel: channel ?? channel_expression,
          identity: electron_identity,
        }),
      ),
    ).toEqual([
      {
        operation: "on",
        channel: "snapshot",
        identity: expect.objectContaining({
          basis: "wrapper-parameter",
          function_name: "registerSnapshot",
          parameter: "deps",
          parameter_index: 0,
          call_sites: 1,
          call_sites_complete: true,
          unresolved_arguments: 0,
        }),
      },
      {
        operation: "handle",
        channel: "channel",
        identity: expect.objectContaining({
          function_name: "transport",
          parameter: "ipc",
          call_sites: 2,
          call_sites_complete: true,
          unresolved_arguments: 1,
        }),
      },
      {
        operation: "handle",
        channel: "escaped",
        identity: expect.objectContaining({
          function_name: "escaped",
          call_sites: 1,
          call_sites_complete: false,
          unresolved_arguments: 0,
        }),
      },
    ]);
    expect(analysis.electron.browser_windows).toMatchObject([
      {
        web_preferences: [
          {
            name: "contextIsolation",
            value: { status: "literal", value: true },
          },
        ],
        electron_identity: {
          basis: "wrapper-parameter",
          function_name: "consent",
          parameter: "Window",
          parameter_index: 1,
          unresolved_arguments: 1,
        },
      },
    ]);
    expect(analysis.electron.context_bridge_apis).toMatchObject([
      {
        api_key: "api",
        members: ["ping"],
        electron_identity: { basis: "wrapper-parameter", parameter: "bridge" },
      },
    ]);
  });

  it("infers Electron APIs from local fallback and object-literal alternatives", () => {
    const analysis = analyzeJavaScriptStaticSource(`
      const electron = require("electron");
      const api = injected.electron ?? { BrowserWindow: electron.BrowserWindow };
      new api.BrowserWindow({ show: false });
      const deps = { ipc: electron.ipcMain };
      deps.ipc.handle("local:ping", () => 0);
      const mixed = flag ? electron.ipcMain : electron.ipcRenderer;
      mixed.on("mixed", () => 0);
    `);

    expect(analysis.electron.browser_windows).toMatchObject([
      {
        electron_identity: {
          basis: "local-alternatives",
          binding: "api",
          unresolved_values: 1,
        },
      },
    ]);
    expect(
      analysis.electron.ipc.filter(
        ({ resolution_basis }) => resolution_basis === undefined,
      ),
    ).toMatchObject([
      {
        channel: "local:ping",
        electron_identity: {
          basis: "local-alternatives",
          binding: "deps",
          unresolved_values: 0,
        },
      },
    ]);
    expect(
      analysis.electron.ipc
        .filter(({ channel }) => channel === "mixed")
        .map(({ side, guard_alternatives }) => ({ side, guard_alternatives })),
    ).toMatchObject([
      { side: "main", guard_alternatives: [[{ expression: "flag" }]] },
      { side: "renderer", guard_alternatives: [[{ expression: "!(flag)" }]] },
    ]);
  });
});

it.each([`deps.ipc = custom;`, `const alias = deps; alias.ipc = custom;`])(
  "does not infer a replaced local dependency as Electron: %s",
  (mutation) => {
    const analysis = analyzeJavaScriptStaticSource(`
    const electron = require('electron');
    const deps = { ipc: electron.ipcMain };
    ${mutation}
    deps.ipc.handle('x', handler);
  `);
    expect(analysis.electron.ipc).toEqual([]);
  },
);
