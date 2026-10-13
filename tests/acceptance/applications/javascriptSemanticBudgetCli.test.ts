import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect } from "vitest";

import { parseEvidence } from "../../../src/domain/evidence.js";
import { javascriptApplicationAnalysisResultSchema } from "../../../src/domain/javascript/javascriptApplicationAnalysis.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { cliTest } from "../../support/cli/cliFixture.js";

// A 448 MiB parent heap gives one Evidence a budget of about 39 MB, which this
// source's semantic facts exceed while the small source fits its share.
cliTest.skipIf(process.versions.bun !== undefined)(
  "bounds semantic facts per source and pages exact coverage and unknowns",
  { timeout: 90_000 },
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-js-semantic-budget-");
    const large = Array.from(
      { length: 2400 },
      (_, index) =>
        `export function method_${String(index)}(input) { const value = input + ${String(index)}; const pair = { value }; return pair.value; }`,
    ).join("\n");
    await writeFile(join(root, "a-large.mjs"), large);
    await writeFile(
      join(root, "b-small.mjs"),
      "export const run = (handlers, key) => handlers[key]();\n",
    );
    const environment = {
      HOME: root,
      XDG_CONFIG_HOME: root,
      XDG_CACHE_HOME: root,
      NODE_OPTIONS: "--max-old-space-size=448 --max-semi-space-size=8",
    };
    const analyzed = await cli.run({
      arguments: ["analyze-javascript-application", root, "--json"],
      environment,
      timeoutMs: 60_000,
    });
    expect(analyzed.exitCode).toBe(0);
    const evidence = parseEvidence(analyzed.json);
    const result = javascriptApplicationAnalysisResultSchema.parse(
      evidence.normalized_result,
    );
    const { coverage } = result.semantic_graph;
    const [largeCoverage, smallCoverage] = coverage.files;
    expect(largeCoverage).toMatchObject({
      module_path: "a-large.mjs",
      status: "truncated",
    });
    expect(smallCoverage).toMatchObject({
      module_path: "b-small.mjs",
      status: "complete",
      omitted_nodes: 0,
    });
    if (
      largeCoverage?.graph_byte_budget == null ||
      largeCoverage.retained_graph_bytes === null
    )
      throw new Error("A truncated source reports its byte budget");
    expect(largeCoverage.retained_graph_bytes).toBeLessThanOrEqual(
      largeCoverage.graph_byte_budget,
    );
    // Every frontier is counted, including those the budget did not retain.
    const dataFlow = largeCoverage.unknowns.find(
      ({ family, reason }) =>
        family === "data-flow" && reason === "unknown-value",
    );
    expect(dataFlow?.total).toBeGreaterThan(dataFlow?.retained ?? 0);
    expect(
      coverage.families.find(({ family }) => family === "data-flow")
        ?.omitted_unknowns,
    ).toBe(
      coverage.files.reduce(
        (total, file) =>
          total +
          file.unknowns
            .filter(({ family }) => family === "data-flow")
            .reduce((sum, count) => sum + count.total - count.retained, 0),
        0,
      ),
    );
    expect(coverage.limits).toContainEqual(
      expect.objectContaining({
        name: "javascript_analysis_evidence_budget_bytes",
        unit: "bytes",
      }),
    );
    // Relations keep their endpoints, so a truncated source still has a
    // connected call and data-flow prefix.
    expect(
      result.semantic_graph.relations.some(({ source_node_id }) =>
        result.semantic_graph.nodes.some(
          ({ node_id, identity }) =>
            node_id === source_node_id &&
            identity.module_path === "a-large.mjs",
        ),
      ),
    ).toBe(true);

    const view = async (collection: string, offset: number, limit: number) => {
      const input = join(root, `${collection}-${String(offset)}.json`);
      await writeFile(
        input,
        JSON.stringify({
          source: { kind: "inline", evidence },
          view: { kind: "page", collection, offset, limit },
        }),
      );
      const response = await cli.run({
        arguments: ["inspect-analysis-view", input, "--json"],
        environment,
        timeoutMs: 60_000,
      });
      expect(response.exitCode).toBe(0);
      return response.json;
    };
    expect(await view("semantic_files", 1, 1)).toMatchObject({
      normalized_result: {
        kind: "page",
        items: [smallCoverage],
        coverage: { total: 2, next_offset: null, exhausted: true },
      },
    });
    // The large source closed its budget before its frontiers were offered, so
    // the retained frontiers all belong to the small source.
    expect(
      coverage.files[0]?.unknowns.every(({ retained }) => retained === 0),
    ).toBe(true);
    expect(await view("semantic_unknowns", 0, 1)).toMatchObject({
      normalized_result: {
        kind: "page",
        items: [{ module_path: "b-small.mjs", family: "call-flow" }],
        coverage: {
          examined: 1,
          total: result.semantic_graph.unknowns.length,
          next_offset: 1,
        },
      },
    });
  },
);
