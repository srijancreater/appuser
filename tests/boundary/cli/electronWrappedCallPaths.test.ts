import { expect } from "vitest";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { writeFixtureFiles } from "../../support/javascriptApplicationFixture.js";
import { cliTest, type TestCli } from "../../support/cli/cliFixture.js";
import { javascriptApplicationAnalysisResultSchema } from "../../../src/domain/javascript/javascriptApplicationAnalysis.js";
import { applicationFeatureTraceResultSchema } from "../../../src/domain/javascript/javascriptFeatureTraceSchemas.js";
import { analyzeJavaScriptDirectory } from "../../support/cli/javascriptApplication.js";

const analyze = async (cli: TestCli, extra = "") => {
  const root = await createTestTempDirectory("rea-electron-wrapped-paths-");
  await writeFixtureFiles(root, {
    "preload.js": `const e=require("electron");
      const sender=channel=>(...args)=>e.ipcRenderer.send(channel,...args);
      e.contextBridge.exposeInMainWorld("desktop",{copy:sender("test:copy"),cut:sender("test:cut")});`,
    "main.js": `const e=require("electron");
      function register(channel,handler){e.ipcMain.addListener(channel,event=>allowed(event)&&handler(event))}
      register("test:copy",event=>event.sender.copy());
      register("test:cut",event=>event.sender.cut());${extra}`,
  });
  const output = await cli.run({
    arguments: ["analyze-javascript-application", root, "--json"],
  });
  expect(output.exitCode).toBe(0);
  const { normalized_result: result } = z
    .object({
      normalized_result: javascriptApplicationAnalysisResultSchema,
    })
    .parse(output.json);
  return { root, application: output.json, ...result };
};

cliTest(
  "traces a wrapped bridge member through a unique IPC channel using the public CLI",
  async ({ cli }) => {
    const { root, application, graph } = await analyze(cli);
    const byId = new Map(graph.nodes.map((n) => [n.node_id, n]));
    const joins = graph.edges.filter(
      (e) => e.evidence.extractor.operation === "join-electron-wrapper-paths",
    );
    expect(joins).toHaveLength(2);
    for (const edge of joins) {
      expect(edge.evidence).toMatchObject({
        state: "inferred",
        authority: "static-relationship-inference",
      });
      expect(edge.properties.pairing_basis).toBe(
        "unique-exact-literal-channel",
      );
      expect(
        byId.get(edge.source_node_id)?.observations[0]?.properties.channel,
      ).toBe(edge.properties.channel);
      expect(
        byId.get(edge.target_node_id)?.observations[0]?.properties.channel,
      ).toBe(edge.properties.channel);
      expect(edge.properties.conditions).toEqual([
        expect.objectContaining({ expression: "allowed(event)" }),
      ]);
    }
    const start = graph.nodes.find((n) =>
      n.observations.some(
        (o) =>
          o.properties.entry === "desktop.copy" &&
          o.properties.step_kind === "exposure",
      ),
    );
    expect(start).toBeDefined();
    const visited = new Set<string>(),
      pending = start ? [start.node_id] : [];
    while (pending.length) {
      const id = pending.pop();
      if (!id || visited.has(id)) continue;
      visited.add(id);
      for (const edge of graph.edges)
        if (edge.source_node_id === id) pending.push(edge.target_node_id);
    }
    expect(
      [...visited].some((id) =>
        byId
          .get(id)
          ?.observations.some((o) => o.label === "ipc-event.sender.copy"),
      ),
    ).toBe(true);
    expect(
      [...visited].some((id) =>
        byId
          .get(id)
          ?.observations.some((o) => o.label === "ipc-event.sender.cut"),
      ),
    ).toBe(false);
    const input = join(root, "trace-input.json");
    await writeFile(
      input,
      JSON.stringify({
        application,
        seed: { kind: "api", value: "desktop.copy", match: "exact" },
        direction: "outgoing",
      }),
    );
    const traced = await cli.run({
      arguments: ["trace-application-feature", input, "--json"],
    });
    expect(traced.exitCode).toBe(0);
    const { normalized_result: trace } = z
      .object({
        normalized_result: applicationFeatureTraceResultSchema,
      })
      .parse(traced.json);
    expect(trace.seed_matches).toHaveLength(1);
    expect(
      trace.paths.some(
        (path) =>
          path.contains_inference &&
          path.node_ids.length > 8 &&
          byId
            .get(path.end_node_id)
            ?.observations.some((o) => o.label === "ipc-event.sender.copy"),
      ),
    ).toBe(true);
  },
);

for (const surface of ["CLI", "stdio MCP"] as const) {
  cliTest(
    `preserves handler ambiguity and short-circuit factory paths through ${surface}`,
    async ({ cli }) => {
      const root = await createTestTempDirectory("rea-electron-branch-paths-");
      await writeFixtureFiles(root, {
        "preload.js": `const e=require("electron");
        e.contextBridge.exposeInMainWorld("empty", {});
        function choose(){
          if(flag)return ()=>e.ipcRenderer.send("test:copy");
          else return ()=>e.ipcRenderer.send("test:cut");
          return ()=>e.ipcRenderer.send("test:dead");
        }
        e.contextBridge.exposeInMainWorld("desktop", {
          choose:choose(),
          ambiguous:()=>e.ipcRenderer.send("test:ambiguous"),
          competing:()=>e.ipcRenderer.send("test:competing"),
          conditional:()=>e.ipcRenderer.send("test:conditional"),
          fallback:()=>e.ipcRenderer.send("test:fallback"),
        });`,
        "main.js": `const e=require("electron");
        const copy=event=>event.sender.copy(), cut=event=>event.sender.cut();
        function register(channel,handler){e.ipcMain.on(channel,handler)}
        register("test:copy",copy);register("test:cut",cut);
        register("test:ambiguous",flag?copy:cut);
        register("test:competing",copy);
        register("test:competing",flag?copy:unknownHandler);
        if(flag) register("test:conditional",copy);
        register("test:fallback",event=>{false ?? event.sender.copy()});`,
      });
      const { graph } = await analyzeJavaScriptDirectory(surface, cli, root);
      const empty = graph.nodes
        .filter((node) => node.kind === "context-bridge-api")
        .flatMap((node) => node.observations)
        .find((observation) => observation.properties.api_key === "empty");
      expect(empty).toMatchObject({
        properties: {
          api_status: "object-literal",
          members: [],
          unknown_members: 0,
          resolution_basis: "direct-syntax",
        },
        evidence: { state: "observed" },
      });
      const joins = graph.edges.filter(
        (edge) =>
          edge.evidence.extractor.operation === "join-electron-wrapper-paths",
      );
      expect(joins.map((edge) => edge.properties.channel).sort()).toEqual([
        "test:copy",
        "test:cut",
      ]);
      const steps = graph.nodes
        .flatMap((node) => node.observations)
        .filter(
          (observation) => observation.properties.step_kind === "terminal",
        );
      expect(
        [
          ...new Set(
            steps
              .filter((step) => step.properties.entry === "desktop.choose")
              .map((step) => step.properties.channel),
          ),
        ].sort(),
      ).toEqual(["test:copy", "test:cut"]);
      for (const [channel, expression] of [
        ["test:copy", "flag"],
        ["test:cut", "!(flag)"],
      ])
        expect(
          steps.find(
            (step) =>
              step.properties.entry === "desktop.choose" &&
              step.properties.channel === channel,
          )?.properties.conditions,
        ).toEqual([expect.objectContaining({ expression })]);
      expect(
        steps.some(
          (step) =>
            step.properties.entry_kind === "ipc-handler" &&
            ["test:ambiguous", "test:fallback"].includes(
              String(step.properties.channel),
            ),
        ),
      ).toBe(false);
    },
  );
}

cliTest(
  "does not join a channel with another untraced compatible handler",
  async ({ cli }) => {
    const { graph } = await analyze(
      cli,
      'e.ipcMain.on("test:copy",event=>unresolved(event));',
    );
    const joins = graph.edges.filter(
      (e) => e.evidence.extractor.operation === "join-electron-wrapper-paths",
    );
    expect(joins.map((e) => e.properties.channel)).toEqual(["test:cut"]);
  },
);

for (const surface of ["CLI", "stdio MCP"] as const)
  cliTest(
    `pairs a generated RPC edge across a global symbol registry through ${surface}`,
    async ({ cli }) => {
      const root = await createTestTempDirectory("rea-electron-registry-edge-");
      await writeFixtureFiles(root, {
        "main-core.cjs": `"use strict";
var dn=require("electron");
function YN(e,t){return{handle:(n,r)=>{e.handle(n,(o,a)=>r(t.senderFacts(o),a))}}}
function JN(e){return e.ipcMain!=null?YN(e.ipcMain,e):YN(dn.ipcMain,e)}
globalThis[Symbol.for("demo.core.modules")]=Object.freeze([{get ipcMainTransport(){return JN}}]);
`,
        "main-app.cjs": `"use strict";
var nlt=Object.create,mT=Object.defineProperty,olt=Object.getOwnPropertyDescriptor,ilt=Object.getOwnPropertyNames,alt=Object.getPrototypeOf,slt=Object.prototype.hasOwnProperty;
var I=(e,t)=>()=>(t||e((t={exports:{}}).exports,t),t.exports),fT=(e,t,r,n)=>{if(t&&typeof t=="object"||typeof t=="function")for(let o of ilt(t))!slt.call(e,o)&&o!==r&&mT(e,o,{get:()=>t[o],enumerable:!(n=olt(t,o))||n.enumerable});return e},E=(e,t,r)=>(r=e!=null?nlt(alt(e)):{},fT(t||!e||!e.__esModule?mT(r,"default",{value:e,enumerable:!0}):r,e));
var oe=I((x,m)=>{m.exports=globalThis[Symbol.for("demo.core.modules")]});
var yd=I((x,m)=>{m.exports=oe()[0]});
var F=E(yd()),Q=require("electron");
function k(){return{noArgs:{schema:null},args:e=>({schema:e})}}
function Uo(e,t){return Object.freeze({kind:"rpc-edge",edge:e,methods:t.methods})}
function S(e,t){return\`dune-rpc:\${e}:m:\${t}\`}
function El(){return(e,t)=>{let r={};for(let[n,o]of Object.entries(t))r[n]={trust:e,run:o};return r}}
function serve(e,t,r){for(let{method:l}of t){let u=r.handlers[l];if(u==null)throw new Error(l);let m=r.trust[u.trust];if(m==null)throw new Error(u.trust);r.transport.handle(S(e,l),async(A,P)=>{if(m.kind==="require"&&!m.test(A))return{ok:!1};return{ok:!0,value:await u.run(P,A)}})}}
function bl(e,t){return serve(e.edge,Object.entries(e.methods).map(([n,{schema:r}])=>({method:n,validate:r})),t)}
var Jv=Uo("main",{methods:{readClipboard:k().noArgs,openExternal:k().args({url:1})}});
var Vr=El();
function trust(){return{appWindow:{kind:"require",test:e=>e.topFrame,denial:"top frame only"}}}
function handlers(e){return Vr("appWindow",{readClipboard:()=>e.clipboard.readText(),openExternal:({url:t})=>e.shell.openExternal(t)})}
function G(e){return bl(Jv,{transport:(0,F.ipcMainTransport)({ipcMain:e.ipcMain??Q.ipcMain,senderFacts:t=>({topFrame:t.senderFrame===t.sender.mainFrame})}),trust:trust(),handlers:handlers(Q)})}
G({});
`,
        "preload.cjs": `"use strict";
var x=require("electron");
function W(e,n){return\`dune-rpc:\${e}:m:\${n}\`}
function r(){return{noArgs:{schema:null},args:e=>({schema:e})}}
function Te(e,t){return Object.freeze({kind:"rpc-edge",edge:e,methods:t.methods})}
function Pt(e){return{invoke:(n,a)=>e.invoke(n,a)}}
function Ke(e,n,o={}){let a={},d=o.measures??null,b=async(I,U)=>{let w=await n.invoke(W(e.edge,I),U);if(w.ok)return w.value;throw new Error("failed")},T=(I,U)=>d==null?b(I,U):b(I,U).then(v=>v);for(let[I,{schema:U}]of Object.entries(e.methods))a[I]=U===null?()=>T(I,{}):w=>T(I,w);return a}
var Xi=Te("main",{methods:{readClipboard:r().noArgs,openExternal:r().args({url:1})}});
x.contextBridge.exposeInMainWorld("desktop",Ke(Xi,Pt(x.ipcRenderer)));
`,
      });
      const { graph, summary } = await analyzeJavaScriptDirectory(
        surface,
        cli,
        root,
      );
      expect(summary.ipc).toMatchObject({
        paired_renderer_transmissions: 2,
        guarded_renderer_transmissions: 0,
        ambiguous_renderer_transmissions: 0,
      });
      const handlers = graph.nodes
        .filter((node) => node.kind === "ipc-handler")
        .flatMap((node) => node.observations)
        .filter((observation) =>
          String(observation.properties.channel).startsWith("dune-rpc:main:m:"),
        );
      expect(
        handlers.map(({ properties }) => properties.channel).sort(),
      ).toEqual([
        "dune-rpc:main:m:openExternal",
        "dune-rpc:main:m:readClipboard",
      ]);
      for (const { properties } of handlers)
        expect(properties.linked_operation).toMatchObject({
          source_path: "main-core.cjs",
        });
      const guarded = graph.nodes
        .flatMap((node) => node.observations)
        .find(
          (observation) =>
            observation.properties.step_kind === "terminal" &&
            observation.properties.entry_kind === "ipc-handler" &&
            observation.properties.channel === "dune-rpc:main:m:readClipboard",
        );
      expect(guarded?.label).toBe("electron.clipboard.readText");
      expect(guarded?.properties.conditions).toEqual([
        expect.objectContaining({
          expression: '!(m.kind==="require"&&!m.test(A))',
        }),
      ]);
    },
  );
