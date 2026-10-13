import { AnalysisOutputError } from "../../domain/analysisErrorCore.js";
import type { ApplicationNode } from "../../domain/javascript/javascriptApplicationGraphSchemas.js";
import type { ElectronCallPath } from "../../domain/javascript/electronStaticAnalysisTypes.js";
import type { JavaScriptArtifactFile } from "../../domain/javascript/javascriptArtifactFiles.js";
import { sha256Text } from "../../domain/javascript/javascriptStaticAnalysisHelpers.js";
import {
  collectElectronIpcRecords,
  unambiguousElectronIpcPairings,
  type ElectronIpcRecord,
} from "./ElectronBoundaryAnalysis.js";
import {
  addElectronInferenceEdge,
  electronFindingSourceNode,
  electronRangeKey,
} from "./ElectronBoundaryGraphContext.js";
import {
  artifactLocalIdentity,
  javascriptAnalysisCoverage,
  type JavaScriptArtifactGraphContext,
  type JavaScriptArtifactGraphCoverage,
} from "./JavaScriptArtifactGraphContext.js";
import { staticInferenceEvidence } from "./JavaScriptArtifactGraphEvidence.js";

interface ProjectedPath {
  readonly file: JavaScriptArtifactFile;
  readonly path: ElectronCallPath;
  readonly coverage: JavaScriptArtifactGraphCoverage;
  readonly nodes: readonly ApplicationNode[];
}

/** Retain context-specific wrapper paths, then join only unique IPC records. */
export const addElectronCallPaths = (
  context: JavaScriptArtifactGraphContext,
): void => {
  const projected: ProjectedPath[] = [];
  for (const { file, javascript } of context.analysis.files) {
    if (javascript === null) continue;
    const coverage = javascriptAnalysisCoverage(javascript);
    for (const path of javascript.electron.call_paths ?? []) {
      const pathId = sha256Text(JSON.stringify(path));
      const nodes = path.steps.map((step, index) => {
        const sourceFile = sourceFileForStep(context, file, step);
        return context.accumulator.addNode({
          kind: "javascript-expression",
          identity: artifactLocalIdentity(
            sourceFile.sha256,
            "electron-call-path-step",
            `${pathId}:${String(index)}`,
          ),
          observations: [
            {
              label: step.label,
              properties: {
                path_id: pathId,
                entry: path.entry,
                entry_kind: path.entry_kind,
                channel: path.channel,
                terminal: path.terminal,
                step_kind: step.kind,
                step_index: index,
                module_key: step.module_key,
                module_runtime: step.module_runtime,
                conditions: path.conditions,
                resolution: "candidate",
              },
              evidence: staticInferenceEvidence({
                sha256: sourceFile.sha256,
                path: sourceFile.path,
                range: step.location,
                operation: "substitute-electron-wrapper",
                coverage,
                limitations: [
                  "Lexical wrapper substitution is a static candidate; guards, runtime overrides and execution remain unverified.",
                ],
              }),
            },
          ],
        });
      });
      const first = nodes[0],
        entry = path.steps[0];
      const owner = entry
        ? electronFindingSourceNode(
            context,
            sourceFileForStep(context, file, entry),
            entry.module_key,
            entry.module_runtime ?? undefined,
          )
        : undefined;
      if (first && entry && owner)
        addElectronInferenceEdge(context, {
          source: owner,
          target: first,
          file: sourceFileForStep(context, file, entry),
          range: entry.location,
          coverage,
          relation: "contains",
          operation: "locate-electron-wrapper-path",
          properties: {
            path_id: pathId,
            entry: path.entry,
            resolution: "candidate",
          },
        });
      for (let i = 1; i < nodes.length; i += 1) {
        const source = nodes[i - 1],
          target = nodes[i],
          previous = path.steps[i - 1],
          step = path.steps[i];
        if (!source || !target || !previous || !step) continue;
        addElectronInferenceEdge(context, {
          source,
          target,
          file: sourceFileForStep(context, file, step),
          range: step.location,
          coverage,
          relation: ["exposure", "factory", "ipc"].includes(previous.kind)
            ? "maps_to"
            : "calls",
          operation: "trace-electron-wrapper-path",
          properties: {
            path_id: pathId,
            entry: path.entry,
            channel: path.channel,
            resolution: "candidate",
            conditions: path.conditions,
          },
        });
      }
      projected.push({ file, path, coverage, nodes });
    }
  }
  for (const { transmission, handler } of unambiguousElectronIpcPairings(
    collectElectronIpcRecords(context.analysis),
  )) {
    const sources = projected.filter(
      (p) => p.path.entry_kind === "bridge-member" && matches(p, transmission),
    );
    const targets = projected.filter(
      (p) => p.path.entry_kind === "ipc-handler" && matches(p, handler),
    );
    for (const from of sources)
      for (const to of targets) {
        const source = from.nodes.at(-1),
          target = to.nodes[0];
        if (!source || !target) continue;
        addElectronInferenceEdge(context, {
          source,
          target,
          file: from.file,
          range: transmission.finding.location,
          coverage: from.coverage,
          relation:
            transmission.finding.mode === "invoke" ? "invokes" : "sends",
          operation: "join-electron-wrapper-paths",
          properties: {
            channel: transmission.finding.channel,
            pairing_basis: "unique-exact-literal-channel",
            resolution: "candidate",
            handler_path:
              handler.finding.linked_operation?.source_path ?? to.file.path,
            conditions: to.path.conditions,
          },
          limitations: [
            "The unique static channel match does not establish runtime registration, sender acceptance, or dispatch.",
          ],
        });
      }
  }
};

const matches = (
  projected: ProjectedPath,
  record: ElectronIpcRecord,
): boolean => {
  const { path } = projected;
  const { finding } = record;
  const invocation = finding.invocation_location;
  const operation = finding.linked_operation;
  const operationPath = operation?.source_path ?? record.file.path;
  const operationLocation = operation?.location ?? finding.location;
  const sourceStepKind =
    finding.mode === "send" || finding.mode === "invoke" ? "terminal" : "ipc";
  return (
    projected.file.path === record.file.path &&
    path.channel === finding.channel &&
    path.steps.some(
      (step) =>
        step.kind === sourceStepKind &&
        (step.source_path ?? projected.file.path) === operationPath &&
        electronRangeKey(step.location) === electronRangeKey(operationLocation),
    ) &&
    (invocation === undefined ||
      path.steps.some(
        (step) =>
          (step.kind === "call" || step.kind === "exposure") &&
          (step.source_path ?? projected.file.path) === record.file.path &&
          electronRangeKey(step.location) === electronRangeKey(invocation),
      ))
  );
};

function sourceFileForStep(
  context: JavaScriptArtifactGraphContext,
  file: JavaScriptArtifactFile,
  step: ElectronCallPath["steps"][number],
): JavaScriptArtifactFile {
  if (step.source_path === undefined) return file;
  const linked = context.filesByPath.get(step.source_path);
  if (linked === undefined || linked.sha256 !== step.source_sha256)
    throw new AnalysisOutputError(
      "analyze_javascript_application",
      "A linked Electron step does not match its retained source artifact.",
    );
  return linked;
}
