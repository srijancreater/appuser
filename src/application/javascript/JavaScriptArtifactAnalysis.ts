import { parseContentSecurityPolicy } from "../../domain/javascript/contentSecurityPolicy.js";
import {
  electronStaticFindingCount,
  type ElectronCallPath,
} from "../../domain/javascript/electronStaticAnalysisTypes.js";
import { createHash } from "node:crypto";

import { moduleResolutionModeForJavaScriptReference } from "../../domain/javascript/javascriptModuleResolutionMode.js";
import { setImmediate } from "node:timers/promises";

import { resolveJavaScriptSourceMapReferences } from "../../domain/javascript/javascriptSourceMapPaths.js";
import { analyzeParsedJavaScriptStaticSourceSteps } from "../../domain/javascript/javascriptStaticAnalysis.js";
import type { JavaScriptCompanionSource } from "../../domain/javascript/javascriptGlobalSymbolLinks.js";
import { globalSymbolRegistryCompanions } from "../../domain/javascript/javascriptGlobalSymbolRegistry.js";
import {
  analyzeParsedJavaScriptSemanticsSteps,
  classifyParsedJavaScriptOpenReceiversSteps,
} from "../../domain/javascript/javascriptSemanticAnalysis.js";
import type { JavaScriptSemanticIr } from "../../domain/javascript/javascriptSemanticIr.js";
import { projectJavaScriptModuleSemantics } from "../../domain/javascript/javascriptModuleSemanticIr.js";
import { parseJavaScriptSource } from "../../domain/javascript/javascriptSourceParser.js";
import { hasValidSourceMapContents } from "../../domain/sourceMapContents.js";
import {
  flattenSourceMapLeaves,
  sourceMapJsonText,
} from "../../domain/sourceMapEnvelope.js";
import type {
  JavaScriptSourceRange,
  JavaScriptSourcePoint,
  JavaScriptStaticAnalysis,
} from "../../domain/javascript/javascriptStaticAnalysisTypes.js";
import { failedJavaScriptStaticAnalysis } from "../../domain/javascript/javascriptStaticAnalysisHelpers.js";
import type {
  JavaScriptArtifactFile,
  JavaScriptArtifactFileSet,
} from "../../domain/javascript/javascriptArtifactFiles.js";
import type {
  AnalyzedJavaScriptArtifactFile,
  JavaScriptArtifactAnalysis,
  JavaScriptModuleArtifactAnalysis,
  JavaScriptModuleSemanticIr,
  JavaScriptHtmlPolicyObservation,
  JavaScriptHtmlScriptObservation,
  JavaScriptJsonModuleObservation,
  JavaScriptPackageObservation,
  JavaScriptSourceMapObservation,
  JavaScriptSourceMapOriginal,
} from "./JavaScriptArtifactAnalysisTypes.js";
import { analyzeJavaScriptJsonModule } from "./JavaScriptJsonModules.js";
import { completeJavaScriptAnalysisSteps } from "./JavaScriptAnalysisControl.js";
import { htmlArtifactReferences } from "../../domain/javascript/htmlArtifactReferences.js";
import type { JavaScriptSourceAnalysisPort } from "../../domain/javascript/javascriptSourceAnalysis.js";
import type { JavaScriptSemanticGraphProjection } from "./JavaScriptSemanticGraphBuilder.js";
import { AnalysisError } from "../../domain/analysisErrorBase.js";
import { projectAnalysisError } from "../../domain/analysisErrorProjection.js";
import {
  AnalysisCancelledError,
  AnalysisResourceConstraintError,
  AnalysisTimeoutError,
} from "../../domain/analysisErrorCore.js";

interface MutableArtifactAnalysis<
  SemanticIr extends JavaScriptModuleSemanticIr,
> {
  readonly files: AnalyzedJavaScriptArtifactFile<SemanticIr>[];
  readonly packages: JavaScriptPackageObservation[];
  readonly jsonModules: JavaScriptJsonModuleObservation[];
  readonly htmlScripts: JavaScriptHtmlScriptObservation[];
  readonly htmlPolicies: JavaScriptHtmlPolicyObservation[];
  readonly sourceMaps: JavaScriptSourceMapObservation[];
  readonly companionLimitations: string[];
  visitedNodes: number;
  findings: number;
  modules: number;
  parseFailures: number;
}

interface ArtifactAnalysisContext<
  SemanticIr extends JavaScriptModuleSemanticIr,
> {
  readonly state: MutableArtifactAnalysis<SemanticIr>;
  readonly projectSemantics: (
    file: JavaScriptArtifactFile,
    ir: JavaScriptSemanticIr,
    paths: readonly ElectronCallPath[] | undefined,
  ) => Generator<void, SemanticIr>;
  readonly companions?: ReadonlyMap<
    string,
    readonly JavaScriptCompanionSource[]
  >;
}

/** Sources that name a global symbol registry key another source names. */
const javascriptCompanionSources = (fileSet: JavaScriptArtifactFileSet) =>
  globalSymbolRegistryCompanions(
    fileSet.files.flatMap((file) =>
      file.kind === "javascript" && file.text.included
        ? [{ path: file.path, text: file.text.value }]
        : [],
    ),
    fileSet.text_bytes_read,
  );

/** Analyze every text source from the artifact without a result quota. */
export const analyzeJavaScriptArtifactFiles = (
  fileSet: JavaScriptArtifactFileSet,
): JavaScriptArtifactAnalysis =>
  analyzeArtifactFiles(fileSet, function* (_file, ir) {
    // The full IR needs no projection; one step keeps the shared protocol.
    yield;
    return ir;
  });

/**
 * Project each file's full IR immediately, retaining only later module facts.
 * Parsing, analysis and each projection pass run as separate steps, so control
 * messages and cancellation are handled within one large file as well.
 */
export const analyzeAndProjectJavaScriptArtifactFiles = async (
  fileSet: JavaScriptArtifactFileSet,
  projectSemantics: (
    file: JavaScriptArtifactFile,
    ir: JavaScriptSemanticIr,
    paths: readonly ElectronCallPath[] | undefined,
  ) => Iterator<void, void> | void,
  beforeFile?: (
    file: JavaScriptArtifactFile,
    completed: number,
    total: number,
  ) => Promise<void>,
  signal?: AbortSignal,
): Promise<JavaScriptModuleArtifactAnalysis> => {
  const state = emptyArtifactAnalysis<JavaScriptModuleSemanticIr>();
  const projectFileSemantics = function* (
    file: JavaScriptArtifactFile,
    ir: JavaScriptSemanticIr,
    paths: readonly ElectronCallPath[] | undefined,
  ): Generator<void, JavaScriptModuleSemanticIr> {
    const projection = projectSemantics(file, ir, paths);
    if (projection !== undefined) while (projection.next().done !== true) yield;
    return projectJavaScriptModuleSemantics(ir);
  };
  const linking = javascriptCompanionSources(fileSet);
  state.companionLimitations.push(...linking.limitations);
  const context = {
    state,
    projectSemantics: projectFileSemantics,
    companions: linking.companions,
  };
  for (const [index, file] of fileSet.files.entries()) {
    // Let progress, cancellation and garbage collection run between files.
    await setImmediate();
    await beforeFile?.(file, index, fileSet.files.length);
    await completeJavaScriptAnalysisSteps(
      analyzeArtifactFileSteps(file, context),
      signal,
    );
  }
  return finalizeArtifactAnalysis(state);
};

/** Analyze sources behind a hard heap boundary, retaining collected facts on interruption. */
export const analyzeAndAdoptJavaScriptArtifactFiles = async (
  fileSet: JavaScriptArtifactFileSet,
  worker: Pick<JavaScriptSourceAnalysisPort, "analyze">,
  projection: JavaScriptSemanticGraphProjection,
  beforeFile: (
    file: JavaScriptArtifactFile,
    completed: number,
    total: number,
  ) => Promise<void>,
  signal?: AbortSignal,
): Promise<{
  readonly analysis: JavaScriptModuleArtifactAnalysis;
  readonly interruption: AnalysisError | null;
}> => {
  const state = emptyArtifactAnalysis<JavaScriptModuleSemanticIr>();
  const linking = javascriptCompanionSources(fileSet);
  const companions = linking.companions;
  state.companionLimitations.push(...linking.limitations);
  let interruption: AnalysisError | null = null;
  const selectedFileCount =
    fileSet.files.length - (fileSet.source_selection?.unselected_files ?? 0);
  let selectedFileIndex = 0;
  for (const file of fileSet.files) {
    try {
      await setImmediate();
      if (classifyOutsideAnalysisScope(file, state, projection)) {
        if (signal?.aborted === true) {
          interruption = new AnalysisCancelledError(
            "analyze_javascript_application",
          );
          break;
        }
        continue;
      }
      if (signal?.aborted === true)
        throw new AnalysisCancelledError("analyze_javascript_application");
      await beforeFile(file, selectedFileIndex++, selectedFileCount);
      if (file.kind !== "javascript" || !file.text.included) {
        const steps = analyzeArtifactFileSteps(file, {
          state,
          projectSemantics: function* (_file, ir) {
            yield;
            return projectJavaScriptModuleSemantics(ir);
          },
        });
        await completeJavaScriptAnalysisSteps(steps, signal);
        continue;
      }
      const result = await worker.analyze(
        file,
        projection.remainingFileNodeBudget(),
        signal,
        companions.get(file.path),
      );
      const facts = result.ok ? result.value : result.error;
      const applicationProjectionFailure = facts.applicationProjectionFailure;
      if (facts.projection !== null)
        projection.adoptFileProjection(file, facts.projection);
      const error = result.ok ? null : result.error.error;
      const limits =
        error instanceof AnalysisResourceConstraintError
          ? error.reportedLimits
          : error instanceof AnalysisTimeoutError
            ? { worker_timeout_ms: error.timeoutMs }
            : null;
      const failure =
        error === null
          ? undefined
          : {
              reason: `${file.path}: ${error.message}`,
              error: projectAnalysisError(error),
              limits,
            };
      state.files.push({
        file,
        javascript: facts.javascript,
        semantic: facts.module === null ? null : { ir: facts.module },
        ...(failure === undefined ? {} : { analysis_failure: failure }),
        ...(applicationProjectionFailure === undefined
          ? {}
          : {
              application_projection_failure: {
                reason: applicationProjectionFailure.message,
                error: projectAnalysisError(applicationProjectionFailure),
                limits: applicationProjectionFailure.reportedLimits,
              },
            }),
      });
      if (failure !== undefined && facts.projection === null)
        projection.recordUnavailableFile(
          file,
          failure.reason,
          failure.limits,
          error instanceof AnalysisResourceConstraintError ||
            error instanceof AnalysisTimeoutError
            ? "resource-limit"
            : "incomplete-module",
        );
      if (facts.javascript !== null) {
        state.visitedNodes += facts.javascript.visited_ast_nodes;
        state.findings +=
          findingCount(facts.javascript) +
          (facts.module?.moduleLinks.length ?? 0);
        state.modules += facts.javascript.bundler_registrations.reduce(
          (count, item) => count + item.modules.length,
          0,
        );
        if (facts.javascript.parse_status === "failed")
          state.parseFailures += 1;
      }
      if (
        error !== null &&
        (!(error instanceof AnalysisResourceConstraintError) ||
          error.reportedLimits?.parent_result_budget_exhausted === true)
      ) {
        interruption = error;
        break;
      }
    } catch (cause: unknown) {
      if (signal?.aborted !== true && !(cause instanceof AnalysisError))
        throw cause;
      interruption =
        signal?.aborted === true
          ? new AnalysisCancelledError("analyze_javascript_application")
          : cause instanceof AnalysisError
            ? cause
            : null;
      if (interruption !== null) {
        state.files.push({
          file,
          javascript: null,
          semantic: null,
          analysis_failure: {
            reason: `${file.path}: ${interruption.message}`,
            error: projectAnalysisError(interruption),
            limits: null,
          },
        });
        projection.recordUnavailableFile(
          file,
          interruption.message,
          null,
          "incomplete-module",
        );
      }
      break;
    }
  }
  if (interruption !== null) {
    const analyzedPaths = new Set(state.files.map(({ file }) => file.path));
    const failure = {
      reason: `Source analysis was interrupted: ${interruption.message}`,
      error: projectAnalysisError(interruption),
      limits:
        interruption instanceof AnalysisResourceConstraintError
          ? interruption.reportedLimits
          : interruption instanceof AnalysisTimeoutError
            ? { worker_timeout_ms: interruption.timeoutMs }
            : null,
    };
    for (const file of fileSet.files) {
      if (analyzedPaths.has(file.path)) continue;
      if (classifyOutsideAnalysisScope(file, state, projection)) continue;
      state.files.push({
        file,
        javascript: null,
        semantic: null,
        analysis_failure: failure,
      });
      if (file.kind === "javascript")
        projection.recordUnavailableFile(
          file,
          failure.reason,
          failure.limits,
          interruption instanceof AnalysisResourceConstraintError ||
            interruption instanceof AnalysisTimeoutError
            ? "resource-limit"
            : "incomplete-module",
        );
    }
  }
  return { analysis: finalizeArtifactAnalysis(state), interruption };
};

const analyzeArtifactFiles = <SemanticIr extends JavaScriptModuleSemanticIr>(
  fileSet: JavaScriptArtifactFileSet,
  projectSemantics: ArtifactAnalysisContext<SemanticIr>["projectSemantics"],
): JavaScriptArtifactAnalysis<SemanticIr> => {
  const state = emptyArtifactAnalysis<SemanticIr>();
  const linking = javascriptCompanionSources(fileSet);
  state.companionLimitations.push(...linking.limitations);
  const context = {
    state,
    projectSemantics,
    companions: linking.companions,
  };
  for (const file of fileSet.files) {
    const steps = analyzeArtifactFileSteps(file, context);
    while (steps.next().done !== true);
  }
  return finalizeArtifactAnalysis(state);
};

const finalizeArtifactAnalysis = <
  SemanticIr extends JavaScriptModuleSemanticIr,
>(
  state: MutableArtifactAnalysis<SemanticIr>,
): JavaScriptArtifactAnalysis<SemanticIr> => {
  return {
    files: state.files,
    packages: state.packages,
    json_modules: state.jsonModules,
    html_scripts: state.htmlScripts,
    html_policies: state.htmlPolicies,
    source_maps: state.sourceMaps,
    visited_ast_nodes: state.visitedNodes,
    findings:
      state.findings + state.htmlScripts.length + state.htmlPolicies.length,
    modules: state.modules,
    parse_failures: state.parseFailures,
    limitations: [
      ...state.companionLimitations,
      "JavaScript and HTML were parsed as inert text; bundle bootstrap code was never executed.",
      "Static paths and relationships may remain unresolved when expressions are dynamic or obfuscated.",
      ...state.files.flatMap(
        ({ analysis_failure, application_projection_failure }) =>
          [analysis_failure, application_projection_failure].flatMap(
            (failure) => (failure === undefined ? [] : [failure.reason]),
          ),
      ),
      ...state.files.flatMap(({ file, javascript }) =>
        javascript === null ||
        javascript.parse_status === "failed" ||
        javascript.constant_folding.status === "available"
          ? []
          : [
              `${file.path}: Constant folding was unavailable (${javascript.constant_folding.reason}); only literal syntax supplied static values.`,
            ],
      ),
    ],
  };
};

function* analyzeArtifactFileSteps<
  SemanticIr extends JavaScriptModuleSemanticIr,
>(
  file: JavaScriptArtifactFile,
  context: ArtifactAnalysisContext<SemanticIr>,
): Generator<void, void> {
  const { state } = context;
  if (classifyOutsideAnalysisScope(file, state)) return;
  addStructuredObservations(file, state);
  if (file.kind === "html" && file.text.included)
    addHtmlReferences(file.path, file.text.value, state);
  if (file.kind === "source-map") addSourceMap(file, context);
  if (file.kind !== "javascript" || !file.text.included) {
    state.files.push({ file, javascript: null, semantic: null });
    return;
  }
  const parsed = parseJavaScriptSource(file.text.value, file.path);
  yield;
  if (parsed === null) {
    const analysis = failedJavaScriptStaticAnalysis();
    state.files.push({ file, javascript: analysis, semantic: null });
    state.parseFailures += 1;
    return;
  }
  const openReceiverFacts =
    yield* classifyParsedJavaScriptOpenReceiversSteps(parsed);
  const analysis = yield* analyzeParsedJavaScriptStaticSourceSteps(
    file.text.value,
    parsed,
    openReceiverFacts,
    context.companions?.get(file.path),
  );
  const staticFindings = findingCount(analysis);
  yield;
  const semantics =
    analysis.parse_status === "complete" || analysis.parse_status === "partial"
      ? yield* analyzeParsedJavaScriptSemanticsSteps(
          parsed,
          moduleResolutionModeForJavaScriptReference(
            file.path,
            "static-import",
          ),
        )
      : null;
  const projected =
    semantics === null
      ? null
      : yield* context.projectSemantics(
          file,
          semantics,
          analysis.electron.call_paths,
        );
  state.files.push({
    file,
    javascript: analysis,
    semantic: projected === null ? null : { ir: projected },
  });
  state.visitedNodes += analysis.visited_ast_nodes;
  state.findings += staticFindings + (semantics?.moduleLinks.length ?? 0);
  state.modules += analysis.bundler_registrations.reduce(
    (count, registration) => count + registration.modules.length,
    0,
  );
  if (analysis.parse_status === "failed") state.parseFailures += 1;
}

const classifyOutsideAnalysisScope = <
  SemanticIr extends JavaScriptModuleSemanticIr,
>(
  file: JavaScriptArtifactFile,
  state: MutableArtifactAnalysis<SemanticIr>,
  projection?: JavaScriptSemanticGraphProjection,
): boolean => {
  if (file.text.included || file.text.reason !== "outside-analysis-scope")
    return false;
  state.files.push({ file, javascript: null, semantic: null });
  if (file.kind === "javascript")
    projection?.recordUnavailableFile(
      file,
      "Source was not analyzed because it is outside the caller-selected source_paths.",
      null,
      "incomplete-module",
    );
  return true;
};

const addSourceMap = (
  file: JavaScriptArtifactFile,
  context: ArtifactAnalysisContext<JavaScriptModuleSemanticIr>,
): void => {
  const sourceMap = parseSourceMap(file);
  context.state.sourceMaps.push(sourceMap);
};

const emptyArtifactAnalysis = <
  SemanticIr extends JavaScriptModuleSemanticIr,
>(): MutableArtifactAnalysis<SemanticIr> => ({
  files: [],
  packages: [],
  jsonModules: [],
  htmlScripts: [],
  htmlPolicies: [],
  sourceMaps: [],
  companionLimitations: [],
  visitedNodes: 0,
  findings: 0,
  modules: 0,
  parseFailures: 0,
});

const addStructuredObservations = (
  file: JavaScriptArtifactFile,
  state: MutableArtifactAnalysis<JavaScriptModuleSemanticIr>,
): void => {
  if (file.kind === "package-json") state.packages.push(parsePackage(file));
  if (file.kind !== "json") return;
  const json = analyzeJavaScriptJsonModule(file);
  state.jsonModules.push(json);
  if (json.status === "invalid") state.parseFailures += 1;
};

const parsePackage = (
  file: JavaScriptArtifactFile,
): JavaScriptPackageObservation => {
  if (!file.text.included)
    return unavailablePackage(file, "Package metadata text was unavailable.");
  let value: unknown;
  try {
    value = JSON.parse(file.text.value);
  } catch (cause: unknown) {
    void cause;
    return invalidPackage(file, "package.json is not valid JSON.");
  }
  if (!isRecord(value))
    return invalidPackage(file, "package.json root is not an object.");
  return {
    path: file.path,
    sha256: file.sha256,
    status: "included",
    name: optionalString(value.name),
    version: optionalString(value.version),
    main: optionalString(value.main),
    renderer:
      optionalString(value.renderer) ??
      optionalString(value.browser) ??
      optionalString(value.module),
    limitation: null,
  };
};

const invalidPackage = (
  file: JavaScriptArtifactFile,
  limitation: string,
): JavaScriptPackageObservation => ({
  ...unavailablePackage(file, limitation),
  status: "invalid",
});

const unavailablePackage = (
  file: JavaScriptArtifactFile,
  limitation: string,
): JavaScriptPackageObservation & { readonly status: "unavailable" } => ({
  path: file.path,
  sha256: file.sha256,
  status: "unavailable",
  name: null,
  version: null,
  main: null,
  renderer: null,
  limitation,
});

const addHtmlReferences = (
  path: string,
  text: string,
  state: Pick<
    MutableArtifactAnalysis<JavaScriptModuleSemanticIr>,
    "htmlScripts" | "htmlPolicies"
  >,
): void => {
  const { scripts, policies, baseHref } = htmlArtifactReferences(text);
  for (const { scriptPath, startOffset, endOffset } of scripts)
    state.htmlScripts.push({
      html_path: path,
      script_path: scriptPath,
      base_href: baseHref,
      location: rangeForOffsets(text, startOffset, endOffset),
    });
  for (const { header, content, startOffset, endOffset } of policies) {
    const parsed = parseContentSecurityPolicy(content, false);
    state.htmlPolicies.push({
      html_path: path,
      policy: {
        mechanism: "html-meta",
        header,
        policy: content,
        policy_expression: null,
        directives: parsed?.directives ?? [],
        concerns: parsed?.concerns ?? [],
        dynamic_parts: 0,
        module_key: null,
        location: rangeForOffsets(text, startOffset, endOffset),
      },
    });
  }
};

const parseSourceMap = (
  file: JavaScriptArtifactFile,
): JavaScriptSourceMapObservation => {
  if (!file.text.included) return unavailableSourceMap(file);
  let value: unknown;
  try {
    value = JSON.parse(sourceMapJsonText(file.text.value));
  } catch (cause: unknown) {
    void cause;
    return invalidSourceMap(file, "Source map is not valid JSON.");
  }
  const maps = flattenSourceMapLeaves(value);
  if (maps === undefined)
    return invalidSourceMap(file, "Source map is not a version 3 map.");
  return collectSourceMapOriginals(file, maps);
};

const collectSourceMapOriginals = (
  file: JavaScriptArtifactFile,
  maps: readonly Readonly<Record<string, unknown>>[],
): JavaScriptSourceMapObservation => {
  const sources: JavaScriptSourceMapOriginal[] = [];
  let declarationIndex = 0;
  for (const map of maps) {
    const names = map.sources;
    if (!Array.isArray(names))
      return invalidSourceMap(file, "Source map has no sources array.");
    const contents = map.sourcesContent;
    if (!hasValidSourceMapContents(names.length, contents))
      return invalidSourceMap(
        file,
        "Source map sourcesContent must contain one string or null entry per source.",
      );
    if (map.sourceRoot != null && typeof map.sourceRoot !== "string")
      return invalidSourceMap(
        file,
        "Source map sourceRoot must be a string or null.",
      );
    const root = typeof map.sourceRoot === "string" ? map.sourceRoot : null;
    const sourceNames: (string | null)[] = [];
    for (const raw of names) {
      if (raw !== null && typeof raw !== "string")
        return invalidSourceMap(
          file,
          "Source map contains a non-string source name.",
        );
      sourceNames.push(raw);
    }
    const references = resolveJavaScriptSourceMapReferences(
      sourceNames,
      root,
      file.path,
    );
    for (const [index, reference] of references.entries()) {
      const rawContent = Array.isArray(contents) ? contents[index] : undefined;
      const content = typeof rawContent === "string" ? rawContent : null;
      sources.push({
        source_index: index,
        declaration_index: declarationIndex++,
        reference,
        content,
        content_sha256: content === null ? null : sha256(content),
      });
    }
  }
  return {
    path: file.path,
    sha256: file.sha256,
    status: "included",
    sources,
    limitation: null,
  };
};

const unavailableSourceMap = (
  file: JavaScriptArtifactFile,
): JavaScriptSourceMapObservation => {
  if (file.text.included)
    throw new TypeError("Expected unavailable source-map text");
  return {
    path: file.path,
    sha256: file.sha256,
    status: "invalid",
    sources: [],
    limitation: "Source-map text could not be decoded as UTF-8.",
  };
};

const invalidSourceMap = (
  file: JavaScriptArtifactFile,
  limitation: string,
): JavaScriptSourceMapObservation => ({
  path: file.path,
  sha256: file.sha256,
  status: "invalid",
  sources: [],
  limitation,
});

const findingCount = (analysis: JavaScriptStaticAnalysis): number =>
  analysis.references.length +
  analysis.endpoints.length +
  analysis.storage.length +
  analysis.role_paths.length +
  analysis.source_map_urls.length +
  analysis.bundler_registrations.length +
  electronStaticFindingCount(analysis.electron);

const rangeForOffsets = (
  text: string,
  start: number,
  end: number,
): JavaScriptSourceRange => ({
  start: pointForOffset(text, start),
  end: pointForOffset(text, end),
});

const pointForOffset = (
  text: string,
  offset: number,
): JavaScriptSourcePoint => {
  const lines = text.slice(0, offset).split(/\r\n|\r|\n/u);
  return { line: lines.length, column: lines.at(-1)?.length ?? 0 };
};

const optionalString = (value: unknown): string | null =>
  typeof value === "string" && value.length > 0 ? value : null;

const sha256 = (value: string): string =>
  createHash("sha256").update(value).digest("hex");

const isRecord = (value: unknown): value is Readonly<Record<string, unknown>> =>
  typeof value === "object" && value !== null && !Array.isArray(value);
