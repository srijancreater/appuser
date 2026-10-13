import { compareUnicodeCodePoints } from "../../domain/unicodeCodePointOrder.js";
import { posix } from "node:path";

import type {
  ElectronIpcFinding,
  ElectronNativeAddonBindingFinding,
} from "../../domain/javascript/electronStaticAnalysisTypes.js";
import type { ElectronBoundarySummary } from "../../domain/javascript/javascriptApplicationAnalysis.js";
import type { JavaScriptModuleArtifactAnalysis } from "./JavaScriptArtifactAnalysisTypes.js";
import type { JavaScriptArtifactFile } from "../../domain/javascript/javascriptArtifactFiles.js";
import { resolveArtifactPathByContext } from "./JavaScriptArtifactPathResolution.js";

/** One IPC fact retaining its exact owning artifact for graph projection. */
export interface ElectronIpcRecord {
  readonly key: string;
  readonly file: JavaScriptArtifactFile;
  readonly finding: ElectronIpcFinding;
}

/** An unambiguous literal renderer-to-main static pairing. */
export interface ElectronIpcPairing {
  readonly transmission: ElectronIpcRecord;
  readonly handler: ElectronIpcRecord;
}

/**
 * Pairing state for one renderer transmission without overclaiming
 * ambiguity. A unique match is guarded when either operation was only
 * reached under unresolved predicates.
 */
export interface ElectronIpcPairingState {
  readonly transmission: ElectronIpcRecord;
  readonly candidates: readonly ElectronIpcRecord[];
  readonly status: "paired" | "guarded" | "ambiguous" | "unpaired";
}

/** Flatten all per-file IPC facts into deterministic application records. */
export const collectElectronIpcRecords = (
  analysis: JavaScriptModuleArtifactAnalysis,
): readonly ElectronIpcRecord[] =>
  analysis.files
    .flatMap(({ file, javascript }) =>
      (javascript?.electron.ipc ?? []).map((finding) => ({
        key: ipcRecordKey(file.path, finding),
        file,
        finding,
      })),
    )
    .sort((left, right) => compareUnicodeCodePoints(left.key, right.key));

/** Match only exact literal channels and retain ambiguous matches separately. */
export const classifyElectronIpcPairings = (
  records: readonly ElectronIpcRecord[],
): readonly ElectronIpcPairingState[] => {
  const handlers = records.filter(isMainHandler);
  return records.filter(isPairableRendererTransmission).map((transmission) => {
    const candidates =
      transmission.finding.channel === null
        ? []
        : handlers.filter(
            (handler) =>
              handler.finding.channel === transmission.finding.channel &&
              compatibleIpcModes(transmission.finding, handler.finding),
          );
    const [candidate] = candidates;
    return {
      transmission,
      candidates,
      status:
        candidate !== undefined && candidates.length === 1
          ? transmission.finding.guard_alternatives === undefined &&
            candidate.finding.guard_alternatives === undefined
            ? "paired"
            : "guarded"
          : candidates.length > 1
            ? "ambiguous"
            : "unpaired",
    };
  });
};

/** Return only pairings supported by one unique literal main handler. */
export const unambiguousElectronIpcPairings = (
  records: readonly ElectronIpcRecord[],
): readonly ElectronIpcPairing[] =>
  classifyElectronIpcPairings(records).flatMap((state) => {
    const handler = state.candidates[0];
    return state.status === "paired" && handler !== undefined
      ? [{ transmission: state.transmission, handler }]
      : [];
  });

/** Summarize static Electron findings without treating gaps as absence. */
export const summarizeElectronBoundaries = (
  analysis: JavaScriptModuleArtifactAnalysis,
): ElectronBoundarySummary => {
  const files = new Map(analysis.files.map(({ file }) => [file.path, file]));
  const javascript = analysis.files.flatMap(({ javascript: value }) =>
    value === null ? [] : [value],
  );
  const windows = javascript.flatMap(
    ({ electron }) => electron.browser_windows,
  );
  const policies = [
    ...javascript.flatMap(({ electron }) => electron.content_security_policies),
    ...analysis.html_policies.map(({ policy }) => policy),
  ];
  const identities = javascript.flatMap(({ electron }) =>
    [
      ...electron.browser_windows,
      ...electron.context_bridge_apis,
      ...electron.ipc,
      ...electron.utility_processes,
    ].map(({ electron_identity: identity }) => identity),
  );
  const bridges = javascript.flatMap(
    ({ electron }) => electron.context_bridge_apis,
  );
  const validations = javascript.flatMap(
    ({ electron }) => electron.sender_validations,
  );
  const utilities = analysis.files.flatMap(({ file, javascript: value }) =>
    (value?.electron.utility_processes ?? []).map((finding) => ({
      file,
      finding,
    })),
  );
  const nativeBindings = analysis.files.flatMap(({ file, javascript: value }) =>
    (value?.electron.native_addon_bindings ?? []).map((finding) => ({
      file,
      finding,
    })),
  );
  const ipc = collectElectronIpcRecords(analysis);
  const pairing = classifyElectronIpcPairings(ipc);
  const literalChannels = new Set(
    ipc.flatMap(({ finding }) =>
      finding.channel === null ? [] : [finding.channel],
    ),
  );
  return {
    browser_windows: windows.filter(({ api }) => api === "BrowserWindow")
      .length,
    web_contents_views: windows.filter(({ api }) => api !== "BrowserWindow")
      .length,
    webview_attach_handlers: javascript.reduce(
      (count, { electron }) => count + electron.webview_attachments.length,
      0,
    ),
    explicit_web_preferences: windows.reduce(
      (count, window) => count + window.web_preferences.length,
      0,
    ),
    preload_entrypoints:
      windows.filter(({ preload_path: path }) => path !== null).length +
      javascript.reduce(
        (count, { electron }) =>
          count +
          electron.webview_attachments.filter(
            ({ preload_path: path }) => path !== null,
          ).length,
        0,
      ),
    context_bridge_apis: bridges.length,
    exposed_api_members: bridges.reduce(
      (count, bridge) => count + bridge.members.length,
      0,
    ),
    ipc: {
      operations: ipc.length,
      literal_channels: literalChannels.size,
      dynamic_channel_operations: ipc.filter(
        ({ finding }) => finding.channel === null,
      ).length,
      renderer_transmissions: ipc.filter(isRendererTransmission).length,
      renderer_listeners: ipc.filter(
        ({ finding }) =>
          finding.side === "renderer" && finding.mode === "listen",
      ).length,
      main_handlers: ipc.filter(isMainHandler).length,
      paired_renderer_transmissions: pairing.filter(
        ({ status }) => status === "paired",
      ).length,
      guarded_renderer_transmissions: pairing.filter(
        ({ status }) => status === "guarded",
      ).length,
      ambiguous_renderer_transmissions: pairing.filter(
        ({ status }) => status === "ambiguous",
      ).length,
      unpaired_literal_renderer_transmissions: pairing.filter(
        ({ status, transmission }) =>
          status === "unpaired" && transmission.finding.channel !== null,
      ).length,
    },
    sender_validation_observations: validations.length,
    utility_processes: utilities.length,
    resolved_utility_entrypoints: utilities.filter(
      ({ file, finding }) =>
        finding.module_path !== null &&
        resolvesToFile({
          file,
          specifier: finding.module_path,
          context: finding.module_resolution_context,
          files,
        }),
    ).length,
    native_addon_bindings: nativeBindings.length,
    resolved_native_addon_bindings: nativeBindings.filter(
      ({ file, finding }) =>
        resolveElectronNativeAddon(file, finding, files).resolved_path !== null,
    ).length,
    inferred_api_identity_findings: identities.filter(
      ({ basis }) => basis !== "module-binding",
    ).length,
    content_security_policies: policies.length,
    content_security_policy_concerns: policies.reduce(
      (count, { concerns }) => count + concerns.length,
      0,
    ),
  };
};

const compatibleIpcModes = (
  transmission: ElectronIpcFinding,
  handler: ElectronIpcFinding,
): boolean =>
  transmission.mode === "invoke"
    ? handler.mode === "handle"
    : transmission.operation === "send-to-host"
      ? false
      : transmission.mode === "send" && handler.mode === "listen";

const isRendererTransmission = ({ finding }: ElectronIpcRecord): boolean =>
  finding.side === "renderer" &&
  (finding.mode === "send" || finding.mode === "invoke");

const isPairableRendererTransmission = (record: ElectronIpcRecord): boolean =>
  isRendererTransmission(record) && record.finding.operation !== "send-to-host";

const isMainHandler = ({ finding }: ElectronIpcRecord): boolean =>
  finding.side === "main" &&
  (finding.mode === "listen" || finding.mode === "handle");

interface ResolveToFileInput {
  readonly file: JavaScriptArtifactFile;
  readonly specifier: string;
  readonly context: "module-specifier" | "filesystem-expression";
  readonly files: ReadonlyMap<string, JavaScriptArtifactFile>;
  readonly kind?: JavaScriptArtifactFile["kind"];
  readonly moduleKind?: "import" | "require";
}

/** Where a JavaScript-side native binding points in the inventory. */
export interface ElectronNativeAddonResolution {
  readonly resolved_path: string | null;
  /** Inventoried `.node` files the loader could select. */
  readonly candidates: readonly string[];
  readonly basis:
    | "specifier"
    | "loader-package-root"
    | "create-require-base-unavailable";
}

// node-gyp-build and bindings search their package's build and prebuild trees.
const LOADER_ADDON =
  /^(?:build\/(?:Release|Debug)|prebuilds\/[^/]+)\/[^/]+\.node$/u;

/**
 * Resolve one native binding. A specifier is resolved as a module or
 * filesystem path. `bindings` and `node-gyp-build` select a file at runtime,
 * so their candidates are the add-ons in the build and prebuild directories of
 * the nearest inventoried package root; one candidate resolves, more remain
 * candidates. `bindings` candidates must also match the requested name.
 */
export const resolveElectronNativeAddon = (
  file: JavaScriptArtifactFile,
  finding: ElectronNativeAddonBindingFinding,
  files: ReadonlyMap<string, JavaScriptArtifactFile>,
): ElectronNativeAddonResolution => {
  if (finding.loader === "bindings" || finding.loader === "node-gyp-build") {
    const root = packageRoot(file.path, files);
    const wanted =
      finding.loader === "bindings" && finding.specifier_status === "literal"
        ? finding.specifier.replace(/\.node$/u, "") + ".node"
        : undefined;
    const candidates =
      root === undefined
        ? []
        : [...files.values()]
            .filter(({ path, kind }) => {
              const relative = root === "" ? path : path.slice(root.length + 1);
              return (
                kind === "native-addon" &&
                (root === "" || path.startsWith(`${root}/`)) &&
                LOADER_ADDON.test(relative) &&
                (wanted === undefined || posix.basename(path) === wanted)
              );
            })
            .map(({ path }) => path)
            .sort(compareUnicodeCodePoints);
    return {
      resolved_path: candidates.length === 1 ? (candidates[0] ?? null) : null,
      candidates,
      basis: "loader-package-root",
    };
  }
  // The classifier does not yet retain createRequire's base filename. A
  // caller-relative fallback could select a different add-on with the same name.
  if (finding.loader === "create-require")
    return {
      resolved_path: null,
      candidates: [],
      basis: "create-require-base-unavailable",
    };
  const resolved =
    finding.specifier_status === "literal"
      ? resolveArtifactPathByContext({
          declaredPath: finding.specifier,
          sourcePath: file.path,
          context:
            finding.loader === "process-dlopen"
              ? "filesystem-expression"
              : "module-specifier",
          files,
          moduleKind: finding.module_kind,
        }).resolved_path
      : null;
  const addon =
    resolved !== null && files.get(resolved)?.kind === "native-addon"
      ? resolved
      : null;
  return {
    resolved_path: addon,
    candidates: addon === null ? [] : [addon],
    basis: "specifier",
  };
};

const packageRoot = (
  path: string,
  files: ReadonlyMap<string, JavaScriptArtifactFile>,
): string | undefined => {
  for (
    let directory = posix.dirname(path);
    ;
    directory = posix.dirname(directory)
  ) {
    const root = directory === "." ? "" : directory;
    if (files.has(root === "" ? "package.json" : `${root}/package.json`))
      return root;
    if (root === "") return undefined;
  }
};

const resolvesToFile = (input: ResolveToFileInput): boolean => {
  const resolved = resolveArtifactPathByContext({
    declaredPath: input.specifier,
    sourcePath: input.file.path,
    context: input.context,
    files: input.files,
    ...(input.moduleKind === undefined ? {} : { moduleKind: input.moduleKind }),
  }).resolved_path;
  return (
    resolved !== null &&
    (input.kind === undefined || input.files.get(resolved)?.kind === input.kind)
  );
};

const ipcRecordKey = (path: string, finding: ElectronIpcFinding): string => {
  const identity = `${path}\0${String(finding.location.start.line)}:${String(finding.location.start.column)}\0${finding.side}\0${finding.operation}\0${finding.channel ?? finding.channel_expression}\0${JSON.stringify(finding.handler_location)}`;
  return finding.invocation_location === undefined
    ? identity
    : `${identity}\0${String(finding.invocation_location.start.line)}:${String(finding.invocation_location.start.column)}`;
};
