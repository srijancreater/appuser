import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect } from "vitest";
import { z } from "zod";

import { parseEvidence } from "../../../src/domain/evidence.js";
import { javascriptApplicationAnalysisResultSchema } from "../../../src/domain/javascript/javascriptApplicationAnalysis.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { cliTest } from "../../support/cli/cliFixture.js";

cliTest.skipIf(process.versions.bun !== undefined).for([
  { laterSources: 1, heapMb: 640, methodsCount: 400, retainGraph: true },
  { laterSources: 10, heapMb: 640, methodsCount: 400, retainGraph: true },
  // The parent cannot retain this whole graph after reserving transient
  // decoding and the next checkpoint, so it offers a byte budget instead.
  { laterSources: 1, heapMb: 448, methodsCount: 1200, retainGraph: false },
])(
  "preserves evidence with $laterSources later checkpoints and a $heapMb MiB parent heap",
  { timeout: 90_000 },
  async ({ laterSources, heapMb, methodsCount, retainGraph }, { cli }) => {
    const root = await createTestTempDirectory("rea-js-checkpoint-reserve-");
    const source = Array.from(
      { length: methodsCount },
      (_, index) =>
        `export function method_${String(index)}(input) { const value = input + ${String(index)}; const pair = { value }; return pair.value; }`,
    ).join("\n");
    const files: readonly (readonly [string, string])[] = [
      ["a-large.mjs", source],
      ...Array.from(
        { length: laterSources },
        (_, index) =>
          [
            `z-tiny-${String(index)}.mjs`,
            `export const tiny${String(index)} = 1;\n`,
          ] as const,
      ),
    ];
    for (const [name, text] of files) await writeFile(join(root, name), text);
    const response = await cli.run({
      arguments: ["analyze", root, "--format", "json"],
      environment: {
        NODE_OPTIONS: `--max-old-space-size=${String(heapMb)} --max-semi-space-size=8`,
      },
      timeoutMs: 60_000,
    });
    expect(response.exitCode).toBe(0);
    const result = javascriptApplicationAnalysisResultSchema.parse(
      parseEvidence(response.json).normalized_result,
    );
    expect(result.statistics.parsed_javascript_files).toBe(laterSources + 1);
    expect(result.statistics.parse_failures).toBe(0);
    const failures = result.graph.nodes.flatMap(({ observations }) =>
      observations.flatMap(({ properties }) =>
        properties.analysis_failure === undefined
          ? []
          : [properties.analysis_failure],
      ),
    );
    const methods = result.semantic_graph.nodes.filter(
      ({ kind, identity }) =>
        kind === "function" && identity.module_path === "a-large.mjs",
    );
    const largeCoverage = result.semantic_graph.coverage.files.find(
      ({ module_path }) => module_path === "a-large.mjs",
    );
    if (retainGraph) {
      expect(methods.map(({ label }) => label).sort()).toEqual(
        Array.from(
          { length: methodsCount },
          (_, index) => `method_${String(index)}`,
        ).sort(),
      );
      expect(largeCoverage?.status).toBe("complete");
    } else {
      // Functions are projected first, so a truncated source keeps them.
      expect(methods.length).toBeGreaterThan(0);
      expect(largeCoverage).toMatchObject({ status: "truncated" });
      if (
        largeCoverage?.graph_byte_budget == null ||
        largeCoverage.retained_graph_bytes === null ||
        largeCoverage.omitted_nodes === null
      )
        throw new Error("A truncated source reports its exact budget use");
      expect(largeCoverage.retained_graph_bytes).toBeLessThanOrEqual(
        largeCoverage.graph_byte_budget,
      );
      expect(largeCoverage.omitted_nodes).toBeGreaterThan(0);
      expect(result.semantic_graph.coverage).toMatchObject({
        status: "partial",
        truncated: true,
        omitted_nodes: largeCoverage.omitted_nodes,
      });
      expect(result.semantic_graph.coverage.limits).toContainEqual(
        expect.objectContaining({
          name: "javascript_analysis_evidence_budget_bytes",
        }),
      );
    }
    expect(
      result.semantic_graph.nodes.some(
        ({ identity, label }) =>
          identity.module_path === `z-tiny-${String(laterSources - 1)}.mjs` &&
          label === `tiny${String(laterSources - 1)}`,
      ),
    ).toBe(true);
    for (const [name, text] of files) {
      const digest = createHash("sha256").update(text).digest("hex");
      const node = result.graph.nodes.find(
        ({ kind, identity }) =>
          kind === "javascript-asset" &&
          identity.strategy === "content-digest" &&
          identity.sha256 === digest,
      );
      expect(node?.observations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            properties: expect.objectContaining({
              path: name,
              parse_status: "complete",
            }),
          }),
        ]),
      );
      expect(failures).toEqual([]);
      expect(await readFile(join(root, name), "utf8")).toBe(text);
    }
    expect(response.stderr).not.toMatch(/FATAL ERROR:.*heap/iu);
  },
);
