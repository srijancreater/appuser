import type { JavaScriptApplicationGraph } from "../../domain/javascript/javascriptApplicationGraph.js";
import type { JsonValue } from "../../domain/jsonValue.js";
import { javascriptDisplayText } from "../../domain/javascript/javascriptAstValues.js";
import {
  createJavaScriptSemanticGraphNode,
  createJavaScriptSemanticGraphRelation,
  JavaScriptSemanticEvidenceContextRegistry,
  javaScriptSemanticNodeId,
} from "../../domain/javascript/javascriptSemanticGraph.js";
import type { JavaScriptSemanticGraphNode } from "../../domain/javascript/javascriptSemanticGraphSchemas.js";
import type { ApplicationGraphEvidence } from "../../domain/javascript/javascriptApplicationEvidenceSchemas.js";
import type {
  JavaScriptSemanticGraphRelation,
  JavaScriptSemanticGraphUnknown,
} from "../../domain/javascript/javascriptSemanticGraphSchemas.js";
import type { JavaScriptSourceRange } from "../../domain/javascript/javascriptStaticAnalysisTypes.js";
import type { JavaScriptArtifactFile } from "../../domain/javascript/javascriptArtifactFiles.js";
import type { SemanticFileGraphBudget } from "./JavaScriptSemanticFileGraphBudget.js";
import {
  JAVASCRIPT_SEMANTIC_RELATION_FAMILIES,
  JAVASCRIPT_SEMANTIC_UNKNOWN_REASONS,
  type JavaScriptSemanticFileProjectionCoverage,
  type JavaScriptSemanticFingerprint,
} from "../../domain/javascript/javascriptSemanticGraphSchemas.js";
import {
  inferredSemanticEvidence,
  observedSemanticEvidence,
  unavailableSemanticRootEvidence,
} from "./JavaScriptSemanticGraphEvidence.js";

/** Mutable local projection state hidden from graph callers. */
export interface SemanticGraphProjectionState {
  readonly nodes: Map<string, JavaScriptSemanticGraphNode>;
  readonly relations: Map<string, JavaScriptSemanticGraphRelation>;
  readonly unknowns: Map<string, JavaScriptSemanticGraphUnknown>;
  readonly evidenceContexts: JavaScriptSemanticEvidenceContextRegistry;
  readonly roots: Set<string>;
  /** Byte admission for the source file being projected; absent when adopting. */
  fileBudget?: SemanticFileGraphBudget;
}

/** Input for one exact artifact-version semantic node. */
export interface SemanticNodeConstructionInput {
  readonly kind: JavaScriptSemanticGraphNode["kind"];
  readonly roleKey: string;
  readonly location: JavaScriptSourceRange | null;
  readonly label: string | null;
  readonly functionNodeId: string | null;
  readonly properties?: Readonly<Record<string, JsonValue>>;
}

/** Input for one directed static semantic relationship. */
export interface SemanticRelationConstructionInput {
  readonly source: JavaScriptSemanticGraphNode | undefined | null;
  readonly target: JavaScriptSemanticGraphNode | undefined | null;
  readonly relation: JavaScriptSemanticGraphRelation["relation"];
  readonly resolution?: JavaScriptSemanticGraphRelation["resolution"];
  readonly evidence?: ApplicationGraphEvidence;
  readonly properties?: Readonly<Record<string, JsonValue>>;
}

/** Create empty projection state; application-node links are bound at finish. */
export const createSemanticGraphProjectionState =
  (): SemanticGraphProjectionState => ({
    nodes: new Map(),
    relations: new Map(),
    unknowns: new Map(),
    evidenceContexts: new JavaScriptSemanticEvidenceContextRegistry(),
    roots: new Set(),
  });

/** Bind retained semantic identities after all application observations exist. */
export const bindSemanticGraphApplicationNodes = (
  state: SemanticGraphProjectionState,
  applicationGraph: Pick<JavaScriptApplicationGraph, "nodes">,
): void => {
  const applicationNodeIdsByLocation = indexApplicationNodes(
    applicationGraph.nodes,
  );
  for (const [identifier, node] of state.nodes) {
    state.nodes.set(identifier, {
      ...node,
      application_node_ids: [
        ...(applicationNodeIdsByLocation.get(
          applicationLocationKey(
            node.identity.artifact_sha256,
            node.identity.module_path,
            node.identity.source_range,
          ),
        ) ?? []),
      ],
    });
  }
};

/** Construct one canonical semantic node backed by an exact artifact file. */
export const constructSemanticGraphNode = (
  file: Pick<JavaScriptArtifactFile, "path" | "sha256">,
  input: SemanticNodeConstructionInput,
  state: SemanticGraphProjectionState,
): JavaScriptSemanticGraphNode =>
  createJavaScriptSemanticGraphNode(
    {
      kind: input.kind,
      identity: {
        artifact_sha256: file.sha256,
        module_path: file.path,
        source_range: input.location,
        role_key: input.roleKey,
      },
      function_node_id: input.functionNodeId,
      application_node_ids: [],
      label: input.label === null ? null : javascriptDisplayText(input.label),
      properties: input.properties ?? {},
      evidence: observedSemanticEvidence(file, input.location),
    },
    state.evidenceContexts,
  );

/** Reuse retained identities and reject a closed budget before allocation. */
export const retainSemanticGraphNode = (
  state: SemanticGraphProjectionState,
  file: Pick<JavaScriptArtifactFile, "path" | "sha256">,
  input: SemanticNodeConstructionInput,
): JavaScriptSemanticGraphNode | null => {
  const identifier = javaScriptSemanticNodeId({
    kind: input.kind,
    identity: {
      artifact_sha256: file.sha256,
      module_path: file.path,
      source_range: input.location,
      role_key: input.roleKey,
    },
  });
  const existing =
    state.nodes.get(identifier) ??
    state.fileBudget?.pendingNodes.get(identifier);
  if (existing !== undefined) return existing;
  if (state.fileBudget?.closed === true) {
    state.fileBudget.omitNode(identifier);
    return null;
  }
  return addSemanticGraphNode(
    state,
    constructSemanticGraphNode(file, input, state),
  );
};

/**
 * Retain one canonical semantic node. Under a file budget, only module roots
 * are charged immediately; other nodes are charged when an admitted fact
 * first references them, so a truncated file keeps connected facts.
 */
export const addSemanticGraphNode = (
  state: SemanticGraphProjectionState,
  node: JavaScriptSemanticGraphNode,
): JavaScriptSemanticGraphNode | null => {
  const budget = state.fileBudget;
  const existing =
    state.nodes.get(node.node_id) ?? budget?.pendingNodes.get(node.node_id);
  if (existing !== undefined) return existing;
  if (budget === undefined) {
    state.nodes.set(node.node_id, node);
    return node;
  }
  if (node.kind !== "module") {
    budget.pendingNodes.set(node.node_id, node);
    return node;
  }
  if (!budget.admitNode(node, state.evidenceContexts)) {
    budget.omitNode(node.node_id);
    return null;
  }
  state.nodes.set(node.node_id, node);
  return node;
};

/** Charge a pending node and its pending function owner before a referencing fact. */
const admitPendingNode = (
  state: SemanticGraphProjectionState,
  budget: SemanticFileGraphBudget,
  nodeId: string,
): boolean => {
  if (state.nodes.has(nodeId)) return true;
  const node = budget.pendingNodes.get(nodeId);
  if (node === undefined) return false;
  if (
    node.function_node_id !== null &&
    !admitPendingNode(state, budget, node.function_node_id)
  )
    return false;
  if (!budget.admitNode(node, state.evidenceContexts)) return false;
  budget.pendingNodes.delete(nodeId);
  state.nodes.set(nodeId, node);
  return true;
};

/** Retain one non-self semantic relationship. */
export const addSemanticGraphRelation = (
  state: SemanticGraphProjectionState,
  input: SemanticRelationConstructionInput,
): void => {
  if (
    input.source === undefined ||
    input.source === null ||
    input.target === undefined ||
    input.target === null ||
    input.source.node_id === input.target.node_id
  )
    return;
  const value = createJavaScriptSemanticGraphRelation(
    {
      source_node_id: input.source.node_id,
      target_node_id: input.target.node_id,
      relation: input.relation,
      resolution: input.resolution ?? "candidate",
      properties: input.properties ?? {},
      evidence:
        input.evidence ??
        inferredSemanticEvidence(
          state.evidenceContexts.resolve(input.source.evidence),
        ),
    },
    state.evidenceContexts,
  );
  if (state.relations.has(value.relation_id)) return;
  const budget = state.fileBudget;
  if (
    budget !== undefined &&
    !(
      admitPendingNode(state, budget, value.source_node_id) &&
      admitPendingNode(state, budget, value.target_node_id) &&
      budget.admit(value, state.evidenceContexts)
    )
  ) {
    budget.omitRelation(value.relation_id);
    return;
  }
  state.relations.set(value.relation_id, value);
};

/** Retain one unresolved frontier, after the file's nodes when budgeted. */
export const addSemanticGraphUnknown = (
  state: SemanticGraphProjectionState,
  unknown: JavaScriptSemanticGraphUnknown,
): void => {
  if (state.unknowns.has(unknown.unknown_id)) return;
  if (state.fileBudget !== undefined)
    state.fileBudget.deferredUnknowns.set(unknown.unknown_id, unknown);
  else state.unknowns.set(unknown.unknown_id, unknown);
};

/**
 * Close one budgeted file: offer fingerprints, then unknown frontiers with the
 * nodes they name, then nodes no admitted fact referenced. Report exact counts.
 */
export const finishSemanticFileBudget = (
  state: SemanticGraphProjectionState,
  budget: SemanticFileGraphBudget,
  fingerprints: readonly JavaScriptSemanticFingerprint[],
): {
  readonly fingerprints: JavaScriptSemanticFingerprint[];
  readonly coverage: JavaScriptSemanticFileProjectionCoverage;
} => {
  const retainedFingerprints = fingerprints.filter(
    (fingerprint) =>
      admitPendingNode(state, budget, fingerprint.function_node_id) &&
      budget.admit(fingerprint, state.evidenceContexts),
  );
  const counts = new Map<string, { total: number; retained: number }>();
  let omittedUnknowns = 0;
  for (const unknown of budget.deferredUnknowns.values()) {
    const key = `${unknown.family}\u0000${unknown.reason}`;
    const count = counts.get(key) ?? { total: 0, retained: 0 };
    count.total += 1;
    counts.set(key, count);
    if (
      (unknown.node_id === null ||
        admitPendingNode(state, budget, unknown.node_id)) &&
      unknown.candidate_node_ids.every((nodeId) =>
        admitPendingNode(state, budget, nodeId),
      ) &&
      budget.admit(unknown, state.evidenceContexts)
    ) {
      count.retained += 1;
      state.unknowns.set(unknown.unknown_id, unknown);
    } else omittedUnknowns += 1;
  }
  budget.deferredUnknowns.clear();
  for (const nodeId of [...budget.pendingNodes.keys()])
    if (!admitPendingNode(state, budget, nodeId)) budget.omitNode(nodeId);
  budget.pendingNodes.clear();
  const omittedFingerprints = fingerprints.length - retainedFingerprints.length;
  const truncated =
    budget.omittedNodes > 0 ||
    budget.omittedRelations > 0 ||
    omittedFingerprints > 0 ||
    omittedUnknowns > 0;
  return {
    fingerprints: retainedFingerprints,
    coverage: {
      status: truncated ? "truncated" : "complete",
      // The offer derives from host heap; recording it only where it bound
      // keeps identical complete results identical across hosts.
      graph_byte_budget: truncated ? budget.limit : null,
      retained_graph_bytes: budget.used,
      omitted_nodes: budget.omittedNodes,
      omitted_relations:
        budget.omittedNodes > 0 ? null : budget.omittedRelations,
      omitted_fingerprints: omittedFingerprints,
      unknowns: JAVASCRIPT_SEMANTIC_RELATION_FAMILIES.flatMap((family) =>
        JAVASCRIPT_SEMANTIC_UNKNOWN_REASONS.flatMap((reason) => {
          const count = counts.get(`${family}\u0000${reason}`);
          return count === undefined ? [] : [{ family, reason, ...count }];
        }),
      ),
    },
  };
};

/** Add a truthful root when no source file could produce semantic IR. */
export const addSemanticFallbackRoot = (
  rootArtifactSha256: string,
  state: SemanticGraphProjectionState,
): void => {
  const node = addSemanticGraphNode(
    state,
    createJavaScriptSemanticGraphNode(
      {
        kind: "module",
        identity: {
          artifact_sha256: rootArtifactSha256,
          module_path: "unknown-semantic-root",
          source_range: null,
          role_key: "artifact-root",
        },
        function_node_id: null,
        application_node_ids: [],
        label: "unavailable semantic root",
        properties: {},
        evidence: unavailableSemanticRootEvidence(rootArtifactSha256),
      },
      state.evidenceContexts,
    ),
  );
  if (node !== null) state.roots.add(node.node_id);
};

const indexApplicationNodes = (
  nodes: JavaScriptApplicationGraph["nodes"],
): ReadonlyMap<string, readonly string[]> => {
  const identifiers = new Map<string, Set<string>>();
  for (const node of nodes) {
    for (const observation of node.observations) {
      const { artifact, location } = observation.evidence;
      if (!artifact.available || !location.available) continue;
      if (location.value.kind === "artifact-path") {
        addApplicationNodeIdentifier(
          identifiers,
          applicationLocationKey(artifact.sha256, location.value.path, null),
          node.node_id,
        );
      }
      if (location.value.kind === "source-range") {
        addApplicationNodeIdentifier(
          identifiers,
          applicationLocationKey(artifact.sha256, location.value.source, {
            start: location.value.start,
            end: location.value.end,
          }),
          node.node_id,
        );
      }
    }
  }
  const indexed = new Map(
    [...identifiers].map(([key, values]) => {
      const sorted = [...values].sort();
      return [key, sorted];
    }),
  );
  return indexed;
};

const addApplicationNodeIdentifier = (
  identifiers: Map<string, Set<string>>,
  key: string,
  nodeId: string,
): void => {
  const values = identifiers.get(key) ?? new Set<string>();
  values.add(nodeId);
  identifiers.set(key, values);
};

const applicationLocationKey = (
  artifactSha256: string,
  path: string,
  range: JavaScriptSourceRange | null,
): string =>
  [
    artifactSha256,
    path,
    range === null
      ? "artifact-path"
      : `${range.start.line}:${range.start.column}-${range.end.line}:${range.end.column}`,
  ].join("\u0000");
