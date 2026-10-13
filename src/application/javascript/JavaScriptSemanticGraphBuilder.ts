import {
  createJavaScriptSemanticGraph,
  createJavaScriptSemanticGraphUnknown,
  sealTransferredJavaScriptSemanticGraphSteps,
  type JavaScriptSemanticGraph,
} from "../../domain/javascript/javascriptSemanticGraph.js";
import type {
  JavaScriptSemanticFileCoverage,
  JavaScriptSemanticFileProjectionCoverage,
  JavaScriptSemanticFingerprint,
  JavaScriptSemanticGraphNode,
} from "../../domain/javascript/javascriptSemanticGraphSchemas.js";
import { compareUnicodeCodePoints } from "../../domain/unicodeCodePointOrder.js";
import { SemanticFileGraphBudget } from "./JavaScriptSemanticFileGraphBudget.js";
import {
  JAVASCRIPT_SEMANTIC_RELATION_FAMILIES,
  JAVASCRIPT_SEMANTIC_RELATION_FAMILY,
  JAVASCRIPT_SEMANTIC_RELATIONS,
} from "../../domain/javascript/javascriptSemanticGraphSchemas.js";
import type {
  JavaScriptSemanticCallArgument,
  JavaScriptSemanticIr,
} from "../../domain/javascript/javascriptSemanticIr.js";
import { sourceRangesEqual as rangesEqual } from "../../domain/javascript/javascriptStaticAnalysisHelpers.js";
import type { JavaScriptApplicationGraph } from "../../domain/javascript/javascriptApplicationGraph.js";
import type { JavaScriptArtifactAnalysis } from "./JavaScriptArtifactAnalysisTypes.js";
import type { JavaScriptArtifactFile } from "../../domain/javascript/javascriptArtifactFiles.js";
import {
  projectSemanticEvents,
  projectSemanticTimers,
} from "./JavaScriptSemanticGraphAsyncProjection.js";
import { projectSemanticChildProcesses } from "./JavaScriptSemanticGraphChildProcessProjection.js";
import {
  projectSemanticBoundaries,
  projectSemanticConfiguration,
  projectSemanticRequests,
} from "./JavaScriptSemanticGraphDataProjection.js";
import { projectSemanticResources } from "./JavaScriptSemanticGraphResourceProjection.js";
import { projectSemanticObjects } from "./JavaScriptSemanticGraphObjectProjection.js";
import { projectSemanticValues } from "./JavaScriptSemanticGraphValueProjection.js";
import { inferredSemanticEvidenceAt } from "./JavaScriptSemanticGraphEvidence.js";
import { observedSemanticEvidence } from "./JavaScriptSemanticGraphEvidence.js";
import {
  partialApplicationCoverage,
  type ApplicationCoverage,
} from "../../domain/javascript/javascriptApplicationEvidenceSchemas.js";
import type { JsonValue } from "../../domain/jsonValue.js";
import {
  JAVASCRIPT_SEMANTIC_NODE_MAXIMUM,
  javaScriptAnalysisCoverageLimits,
} from "../../domain/javascript/javascriptAnalysisResourceControls.js";
import { projectSemanticFunctionFingerprints } from "./JavaScriptSemanticGraphFingerprintProjection.js";
import {
  projectSemanticClosureCaptures,
  projectSemanticFrontiers,
  projectSemanticPromises,
  projectSemanticReturnValues,
  type SemanticFlowProjectionContext,
} from "./JavaScriptSemanticGraphFlowProjection.js";
import {
  createSemanticCallableOwnerLookup,
  createSemanticCallSiteLookup,
  createSemanticNodeRangeLookup,
  semanticFamilyStatus,
} from "./JavaScriptSemanticGraphProjection.js";
import {
  addSemanticFallbackRoot as addFallbackRoot,
  retainSemanticGraphNode as retainNode,
  addSemanticGraphRelation as addRelation,
  createSemanticGraphProjectionState as emptyState,
  finishSemanticFileBudget,
  bindSemanticGraphApplicationNodes,
  type SemanticGraphProjectionState as BuilderState,
} from "./JavaScriptSemanticGraphConstruction.js";
import type { JavaScriptSemanticFileProjection } from "../../domain/javascript/javascriptSemanticFileProjection.js";
import type { ElectronCallPath } from "../../domain/javascript/electronStaticAnalysisTypes.js";
import { projectElectronSemanticCallPaths } from "./JavaScriptSemanticGraphElectronProjection.js";

interface BuilderInput {
  readonly rootArtifactSha256: string;
  readonly applicationGraph: Pick<
    JavaScriptApplicationGraph,
    "graph_id" | "nodes"
  >;
  readonly analysis: JavaScriptArtifactAnalysis;
}

interface FileContext extends SemanticFlowProjectionContext {
  readonly file: JavaScriptArtifactFile;
  readonly ir: JavaScriptSemanticIr;
  readonly state: BuilderState;
  readonly moduleNode: JavaScriptSemanticGraphNode;
  readonly bindingNodes: ReadonlyMap<string, JavaScriptSemanticGraphNode>;
  readonly callableNodes: ReadonlyMap<string, JavaScriptSemanticGraphNode>;
  readonly callSiteNodes: ReadonlyMap<string, JavaScriptSemanticGraphNode>;
  readonly returnSiteNodes: ReadonlyMap<string, JavaScriptSemanticGraphNode>;
  readonly argumentNodes: Map<string, JavaScriptSemanticGraphNode>;
  readonly referenceNodes: JavaScriptSemanticGraphNode[];
  readonly callResolutions: ReadonlyMap<string, "candidate" | "resolved">;
  readonly callableOwnerAt: ReturnType<
    typeof createSemanticCallableOwnerLookup
  >;
}

export const buildJavaScriptSemanticGraph = ({
  rootArtifactSha256,
  applicationGraph,
  analysis,
}: BuilderInput): JavaScriptSemanticGraph => {
  const projection = createJavaScriptSemanticGraphProjection();
  for (const analyzed of analysis.files) {
    if (analyzed.semantic !== null)
      projection.projectFile(
        analyzed.file,
        analyzed.semantic.ir,
        analyzed.javascript?.electron.call_paths,
      );
    else if (
      !analyzed.file.text.included &&
      analyzed.file.text.reason === "outside-analysis-scope"
    )
      projection.recordUnavailableFile(
        analyzed.file,
        "Source was not analyzed because it is outside the caller-selected source_paths.",
        null,
        "incomplete-module",
      );
  }
  return projection.finish(rootArtifactSha256, applicationGraph, []);
};

/** File-local semantic projection that does not retain consumed source IR. */
export interface JavaScriptSemanticGraphProjection {
  /**
   * Semantic nodes the next source may add under the caller-selected node
   * capacities; null when the caller selected none.
   */
  readonly remainingFileNodeBudget: () => number | null;
  /** Adopt decoded file-local facts; final validation and proof remain in this realm. */
  readonly adoptFileProjection: (
    file: JavaScriptArtifactFile,
    projection: JavaScriptSemanticFileProjection,
  ) => void;
  /** Preserve source-bound unknowns for an execution or result-retention failure. */
  readonly recordUnavailableFile: (
    file: JavaScriptArtifactFile,
    reason: string,
    limits: Readonly<Record<string, JsonValue>> | null,
    unknownReason: "resource-limit" | "incomplete-module",
  ) => void;
  /** Project one file without a byte budget. */
  readonly projectFile: (
    file: JavaScriptArtifactFile,
    ir: JavaScriptSemanticIr,
    paths?: readonly ElectronCallPath[],
  ) => void;
  /** Project one file without a byte budget in steps between its projection passes. */
  readonly projectFileSteps: (
    file: JavaScriptArtifactFile,
    ir: JavaScriptSemanticIr,
    paths?: readonly ElectronCallPath[],
  ) => Generator<void, void>;
  /** `budgetLimits` name the limits that offered each truncated file its budget. */
  readonly finish: (
    rootArtifactSha256: string,
    applicationGraph: BuilderInput["applicationGraph"],
    budgetLimits: ApplicationCoverage["limits"],
  ) => JavaScriptSemanticGraph;
  readonly finishImmutableSteps: (
    rootArtifactSha256: string,
    applicationGraph: BuilderInput["applicationGraph"],
    budgetLimits: ApplicationCoverage["limits"],
  ) => Generator<void, JavaScriptSemanticGraph>;
}

/**
 * Caller-selected semantic node capacities. Omitted capacities do not apply;
 * the serialized Evidence byte budget always does.
 */
export interface JavaScriptSemanticNodeLimits {
  readonly totalNodes?: number;
  readonly fileNodes?: number;
}

/** Accumulate semantic nodes while each source IR is still file-local. */
export const createJavaScriptSemanticGraphProjection = (
  capacities: JavaScriptSemanticNodeLimits = {},
): JavaScriptSemanticGraphProjection => {
  for (const value of [capacities.totalNodes, capacities.fileNodes])
    if (
      value !== undefined &&
      (!Number.isSafeInteger(value) ||
        value < 1 ||
        value > JAVASCRIPT_SEMANTIC_NODE_MAXIMUM)
    )
      throw new RangeError("Semantic graph requires valid node capacities");
  const nodeLimits: ApplicationCoverage["limits"] = [
    ...(capacities.totalNodes === undefined
      ? []
      : [
          {
            name: "semantic_graph_node_ceiling",
            value: capacities.totalNodes,
            unit: "items" as const,
          },
        ]),
    ...(capacities.fileNodes === undefined
      ? []
      : [
          {
            name: "semantic_graph_file_node_ceiling",
            value: capacities.fileNodes,
            unit: "items" as const,
          },
        ]),
  ];
  const state = emptyState();
  const remainingFileNodeBudget = (): number | null =>
    nodeLimits.length === 0
      ? null
      : Math.max(
          0,
          Math.min(
            capacities.fileNodes ?? Number.POSITIVE_INFINITY,
            (capacities.totalNodes ?? Number.POSITIVE_INFINITY) -
              state.nodes.size,
          ),
        );
  const fingerprints: JavaScriptSemanticFingerprint[] = [];
  const files: JavaScriptSemanticFileCoverage[] = [];
  let unavailableFiles = 0;
  let resourceTruncatedFiles = 0;
  const executionLimits = new Map<
    string,
    ApplicationCoverage["limits"][number]
  >();
  const projectSourceSteps = function* (
    file: JavaScriptArtifactFile,
    ir: JavaScriptSemanticIr,
    paths: readonly ElectronCallPath[] = [],
  ): Generator<void, void> {
    const projected = yield* projectBudgetedFileSteps(
      file,
      ir,
      state,
      new SemanticFileGraphBudget(null, remainingFileNodeBudget()),
      paths,
    );
    fingerprints.push(...projected.fingerprints);
    files.push(fileCoverage(file, projected.coverage));
  };
  const finishWith = <Value>(
    factory: (input: unknown) => Value,
    rootArtifactSha256: string,
    applicationGraph: BuilderInput["applicationGraph"],
    budgetLimits: ApplicationCoverage["limits"],
  ): Value => {
    bindSemanticGraphApplicationNodes(state, applicationGraph);
    if (state.roots.size === 0) addFallbackRoot(rootArtifactSha256, state);
    const relations = [...state.relations.values()];
    const unknowns = [...state.unknowns.values()];
    type Family = (typeof JAVASCRIPT_SEMANTIC_RELATION_FAMILIES)[number];
    const retainedByFamily = new Map<Family, number>();
    const unknownsByFamily = new Map<Family, number>();
    const omittedUnknownsByFamily = new Map<Family, number>();
    for (const relation of relations) {
      const family = JAVASCRIPT_SEMANTIC_RELATION_FAMILY[relation.relation];
      retainedByFamily.set(family, (retainedByFamily.get(family) ?? 0) + 1);
    }
    for (const unknown of unknowns)
      unknownsByFamily.set(
        unknown.family,
        (unknownsByFamily.get(unknown.family) ?? 0) + 1,
      );
    for (const coverage of files)
      for (const count of coverage.unknowns)
        omittedUnknownsByFamily.set(
          count.family,
          (omittedUnknownsByFamily.get(count.family) ?? 0) +
            count.total -
            count.retained,
        );
    const truncatedFiles = files.filter(
      ({ status }) => status === "truncated",
    ).length;
    const exactNodes = unavailableFiles === 0;
    const exactRelations =
      exactNodes &&
      files.every(({ omitted_relations: omitted }) => omitted !== null);
    const sortedFiles = [...files].sort(
      (left, right) =>
        compareUnicodeCodePoints(left.module_path, right.module_path) ||
        compareUnicodeCodePoints(left.artifact_sha256, right.artifact_sha256),
    );
    const graph = factory({
      schema: "JavaScriptSemanticRelationGraph",
      root_artifact_sha256: rootArtifactSha256,
      application_graph_id: applicationGraph.graph_id,
      root_node_ids: [...state.roots],
      evidence_contexts: state.evidenceContexts.contexts,
      nodes: [...state.nodes.values()],
      relations,
      // The input is transferred to the factory; `fingerprints` is cleared below.
      fingerprints: [...fingerprints],
      unknowns,
      coverage: {
        status:
          truncatedFiles > 0 || unavailableFiles > 0 ? "partial" : "unknown",
        truncated: truncatedFiles > 0 || resourceTruncatedFiles > 0,
        omitted_nodes: exactNodes
          ? files.reduce(
              (total, { omitted_nodes: omitted }) => total + (omitted ?? 0),
              0,
            )
          : null,
        omitted_relations: exactRelations
          ? files.reduce(
              (total, { omitted_relations: omitted }) => total + (omitted ?? 0),
              0,
            )
          : null,
        limits: [
          ...executionLimits.values(),
          ...(truncatedFiles > 0 ? [...budgetLimits, ...nodeLimits] : []),
        ],
        families: JAVASCRIPT_SEMANTIC_RELATION_FAMILIES.map((family) => ({
          family,
          status: semanticFamilyStatus(family),
          retained_relations: retainedByFamily.get(family) ?? 0,
          omitted_relations: truncatedFiles > 0 || !exactNodes ? null : 0,
          retained_unknowns: unknownsByFamily.get(family) ?? 0,
          omitted_unknowns: exactNodes
            ? (omittedUnknownsByFamily.get(family) ?? 0)
            : null,
        })),
        files: sortedFiles,
      },
      limitations: [
        "The semantic graph contains static syntax observations and conservative relationship candidates; it does not claim runtime execution.",
        "Local data flow does not claim control-flow-sensitive reaching definitions or arbitrary dynamic property resolution.",
        "Promise ownership covers explicit unshadowed Promise construction, static factories, aggregation, chaining, and await syntax only.",
        "Function fingerprints are static candidates; equal digests can remain ambiguous and do not prove behavioral equivalence.",
        "Event extraction covers EventEmitter-style literal registrations, removals, and dispatch candidates; dynamic names remain unknown.",
        "Timer extraction covers global or node:timers scheduling and exact local-handle cancellation.",
        "Child-process extraction covers asynchronous node:child_process creation, literal argv/env/stdio options, exit/error listeners, and kill signals.",
        "Configuration extraction covers process.env, process.argv, node:fs reads, and direct logical defaults.",
        "Request extraction covers fetch, WebSocket, node:http/node:https construction, direct option fields, and exact local response consumers.",
        "Boundary extraction covers unshadowed JSON/global coercions plus parse and validation method candidates.",
        "Resource extraction covers built-in filesystem/network acquisition and exact local close/destroy/end handles.",
        ...(truncatedFiles > 0
          ? [
              "Sources whose semantic facts exceeded their serialized byte budget or a caller-selected node capacity keep a source-ordered prefix; coverage.files reports exact omitted counts. Select one source with source_paths to give it the whole budget.",
            ]
          : []),
      ],
    });
    state.nodes.clear();
    state.relations.clear();
    state.unknowns.clear();
    state.roots.clear();
    state.evidenceContexts.clear();
    fingerprints.length = 0;
    files.length = 0;
    return graph;
  };
  return {
    remainingFileNodeBudget,
    adoptFileProjection: (file, projection) => {
      const offered = remainingFileNodeBudget();
      if (
        offered !== null &&
        projection.nodes.filter(({ node_id }) => !state.nodes.has(node_id))
          .length > offered
      )
        throw new RangeError(
          "Transferred semantic nodes exceed the offered node capacity",
        );
      for (const context of projection.evidenceContexts)
        state.evidenceContexts.adopt(context);
      for (const node of projection.nodes) state.nodes.set(node.node_id, node);
      for (const relation of projection.relations)
        state.relations.set(relation.relation_id, relation);
      for (const unknown of projection.unknowns)
        state.unknowns.set(unknown.unknown_id, unknown);
      for (const root of projection.roots) state.roots.add(root);
      fingerprints.push(...projection.fingerprints);
      files.push(fileCoverage(file, projection.coverage));
    },
    recordUnavailableFile: (file, reason, limits, unknownReason) => {
      const retainedLimits = javaScriptAnalysisCoverageLimits(limits);
      for (const limit of retainedLimits) {
        executionLimits.set(
          JSON.stringify([limit.name, limit.value, limit.unit]),
          limit,
        );
      }
      const module =
        remainingFileNodeBudget() === 0
          ? null
          : retainNode(state, file, {
              kind: "module",
              roleKey: "module",
              location: null,
              label: file.path,
              functionNodeId: null,
            });
      if (module !== null) state.roots.add(module.node_id);
      const evidence = {
        ...observedSemanticEvidence(file, null),
        authority: "unknown" as const,
        state: "unknown" as const,
        confidence: "unknown" as const,
        coverage: partialApplicationCoverage(retainedLimits, null),
        limitations: [reason],
      };
      for (const family of JAVASCRIPT_SEMANTIC_RELATION_FAMILIES) {
        const unknown = createJavaScriptSemanticGraphUnknown(
          {
            node_id: module?.node_id ?? null,
            family,
            relation_kinds: JAVASCRIPT_SEMANTIC_RELATIONS.filter(
              (relation) =>
                JAVASCRIPT_SEMANTIC_RELATION_FAMILY[relation] === family,
            ),
            reason: unknownReason,
            detail: reason,
            candidate_node_ids: [],
            evidence,
          },
          state.evidenceContexts,
        );
        state.unknowns.set(unknown.unknown_id, unknown);
      }
      files.push({
        module_path: file.path,
        artifact_sha256: file.sha256,
        status: "unavailable",
        graph_byte_budget: null,
        retained_graph_bytes: null,
        omitted_nodes: null,
        omitted_relations: null,
        omitted_fingerprints: null,
        unknowns: JAVASCRIPT_SEMANTIC_RELATION_FAMILIES.map((family) => ({
          family,
          reason: unknownReason,
          total: 1,
          retained: 1,
        })),
      });
      unavailableFiles += 1;
      if (unknownReason === "resource-limit" && retainedLimits.length > 0)
        resourceTruncatedFiles += 1;
    },
    projectFile: (file, ir, paths) => {
      const steps = projectSourceSteps(file, ir, paths);
      while (steps.next().done !== true);
    },
    projectFileSteps: projectSourceSteps,
    finish: (rootArtifactSha256, applicationGraph, budgetLimits) =>
      finishWith(
        createJavaScriptSemanticGraph,
        rootArtifactSha256,
        applicationGraph,
        budgetLimits,
      ),
    finishImmutableSteps: (
      rootArtifactSha256,
      applicationGraph,
      budgetLimits,
    ) =>
      finishWith(
        sealTransferredJavaScriptSemanticGraphSteps,
        rootArtifactSha256,
        applicationGraph,
        budgetLimits,
      ),
  };
};

const fileCoverage = (
  file: JavaScriptArtifactFile,
  coverage: JavaScriptSemanticFileProjectionCoverage,
): JavaScriptSemanticFileCoverage => ({
  module_path: file.path,
  artifact_sha256: file.sha256,
  ...coverage,
});

/**
 * Project one source within the offered serialized-byte budget and
 * caller-selected node capacity (null: unbounded), retaining no full IR.
 */
export function* projectJavaScriptSemanticFileSteps(
  file: JavaScriptArtifactFile,
  ir: JavaScriptSemanticIr,
  graphByteBudget: number | null,
  nodeBudget: number | null,
  paths: readonly ElectronCallPath[] = [],
): Generator<void, JavaScriptSemanticFileProjection> {
  const state = emptyState();
  const budget = new SemanticFileGraphBudget(graphByteBudget, nodeBudget);
  const projected = yield* projectBudgetedFileSteps(
    file,
    ir,
    state,
    budget,
    paths,
  );
  return {
    roots: [...state.roots],
    // Refused facts may have interned provenance that no retained fact uses.
    evidenceContexts: state.evidenceContexts.contexts.filter(({ context_id }) =>
      budget.references(context_id),
    ),
    nodes: [...state.nodes.values()],
    relations: [...state.relations.values()],
    unknowns: [...state.unknowns.values()],
    fingerprints: projected.fingerprints,
    coverage: projected.coverage,
  };
}

/** Project one file, then offer its fingerprints and deferred unknown frontiers. */
function* projectBudgetedFileSteps(
  file: JavaScriptArtifactFile,
  ir: JavaScriptSemanticIr,
  state: BuilderState,
  budget: SemanticFileGraphBudget,
  paths: readonly ElectronCallPath[],
): Generator<
  void,
  {
    readonly fingerprints: JavaScriptSemanticFingerprint[];
    readonly coverage: JavaScriptSemanticFileProjectionCoverage;
  }
> {
  state.fileBudget = budget;
  try {
    const candidates = yield* projectFileSteps(file, ir, state, paths);
    return finishSemanticFileBudget(state, budget, candidates);
  } finally {
    delete state.fileBudget;
  }
}

function* projectFileSteps(
  file: JavaScriptArtifactFile,
  ir: JavaScriptSemanticIr,
  state: BuilderState,
  paths: readonly ElectronCallPath[],
): Generator<void, JavaScriptSemanticFingerprint[]> {
  yield;
  const moduleNode = retainNode(state, file, {
    kind: "module",
    roleKey: "module",
    location: null,
    label: file.path,
    functionNodeId: null,
  });
  if (moduleNode === null) return [];
  state.roots.add(moduleNode.node_id);
  yield* projectElectronSemanticCallPaths(file, paths, state);
  // Node creation keeps source order, which the per-file byte budget relies
  // on; yields between nodes do not change it.
  const callableNodes = new Map<string, JavaScriptSemanticGraphNode>();
  for (const [index, callable] of ir.callables.entries()) {
    if (index % 64 === 0) yield;
    const node = retainNode(state, file, {
      kind: "function",
      roleKey: `callable:${callable.callableId}`,
      location: callable.location,
      label: callable.name,
      functionNodeId: null,
      // The label is display text; keep the exact name, which may be "".
      properties: { name: callable.name },
    });
    if (node !== null) callableNodes.set(callable.callableId, node);
  }
  const callableOwnerAt = createSemanticCallableOwnerLookup(ir, callableNodes);
  const bindingNodes = new Map<string, JavaScriptSemanticGraphNode>();
  for (const [index, binding] of ir.bindings.entries()) {
    if (index % 64 === 0) yield;
    const location = binding.definitions[0]?.location ?? null;
    const kind = binding.kind === "parameter" ? "parameter" : "binding";
    const owner = callableOwnerAt(location);
    const node = retainNode(state, file, {
      kind,
      roleKey: `binding:${binding.bindingId}`,
      location,
      label: binding.name,
      functionNodeId: owner?.node_id ?? null,
    });
    if (node !== null) bindingNodes.set(binding.bindingId, node);
  }
  const returnSiteNodes = yield* createReturnSiteNodes(
    file,
    ir,
    callableNodes,
    state,
  );
  const callSiteNodes = yield* createCallSiteNodes(
    file,
    ir,
    callableNodes,
    state,
  );
  const definitions: Omit<FileContext, "referenceNodesWithin"> = {
    file,
    ir,
    state,
    moduleNode,
    bindingNodes,
    callableNodes,
    callSiteNodes,
    returnSiteNodes,
    argumentNodes: new Map(),
    referenceNodes: [],
    callResolutions: new Map(
      ir.callSites.map((call) => [
        call.callSiteId,
        call.resolution === "exact" ? "resolved" : "candidate",
      ]),
    ),
    callableOwnerAt,
    callSiteAt: createSemanticCallSiteLookup(ir, callSiteNodes),
  };
  yield* projectDefinitionsAndReferences(definitions);
  const context: FileContext = {
    ...definitions,
    referenceNodesWithin: createSemanticNodeRangeLookup(
      definitions.referenceNodes,
    ),
  };
  // Each pass completes before the next starts, so yielding between passes
  // keeps projection order and results unchanged.
  for (const project of FILE_PROJECTION_PASSES) {
    yield;
    const steps = project(context);
    if (steps !== undefined) while (steps.next().done !== true) yield;
  }
  yield;
  return projectSemanticFunctionFingerprints(
    file,
    ir,
    callableNodes,
    state.evidenceContexts,
  );
}

function* createReturnSiteNodes(
  file: JavaScriptArtifactFile,
  ir: JavaScriptSemanticIr,
  callables: ReadonlyMap<string, JavaScriptSemanticGraphNode>,
  state: BuilderState,
): Generator<void, Map<string, JavaScriptSemanticGraphNode>> {
  const result = new Map<string, JavaScriptSemanticGraphNode>();
  for (const [index, callable] of ir.callables.entries()) {
    if (index % 64 === 0) yield;
    const owner = callables.get(callable.callableId);
    if (owner === undefined) continue;
    for (const site of callable.returnSites) {
      const identifier = site.returnSiteId;
      const node = retainNode(state, file, {
        kind: "return-site",
        roleKey: identifier,
        location: site.location,
        label: "return",
        functionNodeId: owner.node_id,
      });
      if (node !== null) result.set(identifier, node);
    }
  }
  return result;
}

function* createCallSiteNodes(
  file: JavaScriptArtifactFile,
  ir: JavaScriptSemanticIr,
  callables: ReadonlyMap<string, JavaScriptSemanticGraphNode>,
  state: BuilderState,
): Generator<void, Map<string, JavaScriptSemanticGraphNode>> {
  const result = new Map<string, JavaScriptSemanticGraphNode>();
  for (const [index, call] of ir.callSites.entries()) {
    if (index % 64 === 0) yield;
    const owner =
      call.callerCallableId === null
        ? null
        : (callables.get(call.callerCallableId)?.node_id ?? null);
    const node = retainNode(state, file, {
      kind: "call-site",
      roleKey: `call:${call.callSiteId}`,
      location: call.location,
      label: call.kind,
      functionNodeId: owner,
    });
    if (node !== null) result.set(call.callSiteId, node);
  }
  return result;
}

function* projectDefinitionsAndReferences(
  context: Omit<FileContext, "referenceNodesWithin">,
): Generator<void, void> {
  for (const [bindingIndex, binding] of context.ir.bindings.entries()) {
    if (bindingIndex % 64 === 0) yield;
    const bindingNode = context.bindingNodes.get(binding.bindingId);
    if (bindingNode === undefined) continue;
    for (const [index, definition] of binding.definitions.entries()) {
      const definitionNode = retainNode(context.state, context.file, {
        kind: "expression",
        roleKey: `definition:${binding.bindingId}:${String(index)}`,
        location: definition.location,
        label: definition.kind,
        functionNodeId: bindingNode.function_node_id,
      });
      addRelation(context.state, {
        source: definitionNode,
        target: bindingNode,
        relation: "defines",
        resolution: "resolved",
      });
    }
  }
  for (const [index, reference] of context.ir.references.entries()) {
    if (index % 64 === 0) yield;
    const expression = retainNode(context.state, context.file, {
      kind: "expression",
      roleKey: `reference:${String(index)}:${reference.role}:${reference.name}`,
      location: reference.location,
      label: reference.name,
      functionNodeId:
        context.callableOwnerAt(reference.location)?.node_id ?? null,
    });
    const binding =
      reference.bindingId === null
        ? undefined
        : context.bindingNodes.get(reference.bindingId);
    if (expression !== null) context.referenceNodes.push(expression);
    if (binding === undefined || expression === null) continue;
    if (reference.role === "read")
      addRelation(context.state, {
        source: binding,
        target: expression,
        relation: "reads",
        resolution: "resolved",
        evidence: inferredSemanticEvidenceAt(context.file, reference.location),
      });
    else
      addRelation(context.state, {
        source: expression,
        target: binding,
        relation: "writes",
        resolution: "resolved",
      });
  }
}

const projectCalls = (context: FileContext): void => {
  for (const call of context.ir.callSites) {
    const callNode = context.callSiteNodes.get(call.callSiteId);
    if (callNode === undefined) continue;
    for (const callableId of call.calleeCallableIds) {
      const callable = context.callableNodes.get(callableId);
      addRelation(context.state, {
        source: callNode,
        target: callable,
        relation: "calls",
        resolution: call.resolution === "exact" ? "resolved" : "candidate",
      });
    }
    for (const argument of call.arguments) {
      const argumentNode = createArgumentNode(
        context,
        callNode,
        call.callSiteId,
        argument,
      );
      if (argumentNode !== null)
        context.argumentNodes.set(
          `${call.callSiteId}\u0000${String(argument.index)}`,
          argumentNode,
        );
      const references = context.referenceNodesWithin(argument.location);
      for (const reference of references)
        addRelation(context.state, {
          source: reference,
          target: argumentNode,
          relation: "aliases",
          resolution:
            references.length === 1 &&
            rangesEqual(reference.identity.source_range, argument.location)
              ? "resolved"
              : "candidate",
        });
    }
  }
  for (const flow of context.ir.argumentFlows) {
    const argument = context.argumentNodes.get(
      `${flow.callSiteId}\u0000${String(flow.argumentIndex)}`,
    );
    const parameter = context.bindingNodes.get(flow.parameterBindingId);
    addRelation(context.state, {
      source: argument,
      target: parameter,
      relation: "argument-to-parameter",
      resolution: context.callResolutions.get(flow.callSiteId) ?? "candidate",
    });
  }
  for (const flow of context.ir.callReturnFlows)
    addRelation(context.state, {
      source: context.returnSiteNodes.get(flow.returnSiteId),
      target: context.callSiteNodes.get(flow.callSiteId),
      relation: "returns-to-call",
      resolution: context.callResolutions.get(flow.callSiteId) ?? "candidate",
    });
  for (const flow of context.ir.callResultFlows)
    addRelation(context.state, {
      source: context.callSiteNodes.get(flow.callSiteId),
      target: context.bindingNodes.get(flow.bindingId),
      relation: "aliases",
      resolution: context.callResolutions.get(flow.callSiteId) ?? "candidate",
    });
  projectSemanticReturnValues(context);
};

const createArgumentNode = (
  context: FileContext,
  callNode: JavaScriptSemanticGraphNode,
  callSiteId: string,
  argument: JavaScriptSemanticCallArgument,
): JavaScriptSemanticGraphNode | null =>
  retainNode(context.state, context.file, {
    kind: "expression",
    roleKey: `argument:${callSiteId}:${String(argument.index)}`,
    location: argument.location,
    label: argument.spread
      ? "spread argument"
      : `argument ${String(argument.index)}`,
    functionNodeId: callNode.function_node_id,
  });

/** Per-file projection passes, run in this order with a yield between each. */
const FILE_PROJECTION_PASSES: readonly ((
  context: FileContext,
) => Iterator<void, void> | void)[] = [
  projectSemanticValues,
  projectSemanticObjects,
  projectCalls,
  projectSemanticPromises,
  projectSemanticEvents,
  projectSemanticTimers,
  projectSemanticChildProcesses,
  projectSemanticConfiguration,
  projectSemanticRequests,
  projectSemanticBoundaries,
  projectSemanticResources,
  projectSemanticClosureCaptures,
  projectSemanticFrontiers,
];
