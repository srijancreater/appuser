import type * as t from "@babel/types";
import type { JavaScriptRpcScan } from "./javascriptRpcEndpoints.js";
import type { JavaScriptStaticConstantReader } from "./javascriptStaticConstants.js";

import type {
  JavaScriptBundlerRegistration,
  JavaScriptRolePath,
  JavaScriptStaticAnalysis,
  JavaScriptStaticEndpoint,
  JavaScriptStaticReference,
  JavaScriptStaticStorage,
} from "./javascriptStaticAnalysisTypes.js";
import type {
  ElectronCallPath,
  ElectronBrowserWindowFinding,
  ElectronCalleeBinding,
  ElectronContextBridgeFinding,
  ElectronIpcFinding,
  ElectronNativeAddonBindingFinding,
  ElectronSenderValidationFinding,
  ElectronUtilityProcessFinding,
  ElectronWebviewAttachFinding,
  ElectronContentSecurityPolicyFinding,
} from "./electronStaticAnalysisTypes.js";
import { JavaScriptModuleRangeIndex } from "./javascriptStaticAnalysisFindings.js";

/** Source offsets for one recovered bundle module factory. */
export interface JavaScriptModuleRange {
  readonly start: number;
  readonly end: number;
  readonly key: string;
  readonly runtime: string;
  readonly requireName: string | null;
}

/** Static finding retained with its source offset until module attribution. */
export interface LocatedJavaScriptFinding<Value> {
  readonly offset: number;
  readonly value: Value;
}

/** Mutable collections used during one inert AST traversal. */
export interface JavaScriptAnalysisAccumulator {
  electronCallPaths?: readonly ElectronCallPath[];
  electronCallPathLimitReached?: boolean;
  readonly references: LocatedJavaScriptFinding<JavaScriptStaticReference>[];
  readonly endpoints: LocatedJavaScriptFinding<JavaScriptStaticEndpoint>[];
  readonly storage: LocatedJavaScriptFinding<JavaScriptStaticStorage>[];
  readonly roles: LocatedJavaScriptFinding<JavaScriptRolePath>[];
  readonly sourceMaps: JavaScriptStaticAnalysis["source_map_urls"][number][];
  readonly registrations: JavaScriptBundlerRegistration[];
  readonly browserWindows: LocatedJavaScriptFinding<ElectronBrowserWindowFinding>[];
  readonly contextBridgeApis: LocatedJavaScriptFinding<ElectronContextBridgeFinding>[];
  readonly ipc: LocatedJavaScriptFinding<ElectronIpcFinding>[];
  readonly senderValidations: LocatedJavaScriptFinding<ElectronSenderValidationFinding>[];
  readonly utilityProcesses: LocatedJavaScriptFinding<ElectronUtilityProcessFinding>[];
  readonly nativeAddonBindings: LocatedJavaScriptFinding<ElectronNativeAddonBindingFinding>[];
  readonly webviewAttachments: LocatedJavaScriptFinding<ElectronWebviewAttachFinding>[];
  readonly contentSecurityPolicies: LocatedJavaScriptFinding<ElectronContentSecurityPolicyFinding>[];
  /** Nodes already reported as part of a policy. */
  readonly policyNodes: WeakSet<t.Node>;
  readonly moduleRangeIndex: JavaScriptModuleRangeIndex;
  /** `preload` attributes of audio and video elements, which are not scripts. */
  readonly mediaElementPreloads: WeakSet<t.Node>;
  /** Value expressions already reported as call-site or route endpoints. */
  readonly consumedValueNodes: WeakSet<t.Node>;
  readonly seen: Set<string>;
  visitedNodes: number;
  unknownFindings: number;
}

/** Object literal bound to an identifier in a contextBridge API argument. */
export interface ElectronApiObject {
  readonly object: t.ObjectExpression;
  /** A visible member write or mutator call targets the bound object. */
  readonly memberWrites: boolean;
}

/** A call that loads a module through a native or CommonJS loader. */
export interface JavaScriptNativeLoaderCall {
  readonly loader: NonNullable<ElectronNativeAddonBindingFinding["loader"]>;
  /** How the callee was tied to the loader. */
  readonly basis: NonNullable<
    ElectronNativeAddonBindingFinding["loader_basis"]
  >;
}

/** Electron facts recovered from lexical bindings before the finding scan. */
export interface JavaScriptElectronSemanticFacts {
  /** Parsed lexical owner of an identifier, shared by finding consumers. */
  readonly bindingId: (node: t.Identifier) => string | undefined;
  readonly callees: ReadonlyMap<number, ElectronCalleeBinding>;
  /** Bound API objects by identifier offset. */
  readonly apiObjects: ReadonlyMap<number, ElectronApiObject>;
  /** Native and CommonJS loader calls; nested calls can share an offset. */
  readonly loaders: WeakMap<t.Node, JavaScriptNativeLoaderCall>;
}

/** Shared source and accumulator for helper inspections. */
export interface JavaScriptFindingContext {
  readonly rpcScan: JavaScriptRpcScan;
  readonly source: string;
  /** Exact literal or derived values of finding expressions. */
  readonly constants: JavaScriptStaticConstantReader;
  readonly accumulator: JavaScriptAnalysisAccumulator;
  readonly openReceiverFacts?: ReadonlyMap<
    number,
    | "window"
    | "indexed-db"
    | "cache-storage"
    | "local"
    | "local-indexed-db"
    | "local-cache-storage"
  >;
  /** Classified Electron callee identities and bound bridge API objects. */
  readonly electron?: JavaScriptElectronSemanticFacts;
}

/** Candidate import, require, worker, or service-worker reference. */
export interface JavaScriptReferenceInput {
  readonly node: t.Node;
  readonly kind: JavaScriptStaticReference["kind"];
  readonly specifier: string | undefined;
}

/** Candidate route or network endpoint literal. */
export interface JavaScriptEndpointInput {
  readonly node: t.Node;
  readonly kind: JavaScriptStaticEndpoint["kind"];
  readonly value: string;
  readonly expression: string | null;
  readonly mechanism: string;
}

/** Values required to append one module-attributable static finding. */
export interface LocatedJavaScriptFindingInput<
  Value extends { readonly module_key: string | null },
> {
  readonly collection: LocatedJavaScriptFinding<Value>[];
  readonly key: string;
  readonly node: t.Node;
  readonly value: Value;
}

/** Create isolated mutable state for one source analysis. */
export const createJavaScriptAnalysisAccumulator = (
  sourceLength: number,
): JavaScriptAnalysisAccumulator => ({
  references: [],
  endpoints: [],
  storage: [],
  roles: [],
  sourceMaps: [],
  registrations: [],
  browserWindows: [],
  contextBridgeApis: [],
  ipc: [],
  senderValidations: [],
  utilityProcesses: [],
  nativeAddonBindings: [],
  webviewAttachments: [],
  contentSecurityPolicies: [],
  policyNodes: new WeakSet(),
  moduleRangeIndex: new JavaScriptModuleRangeIndex(sourceLength),
  mediaElementPreloads: new WeakSet(),
  consumedValueNodes: new WeakSet(),
  seen: new Set(),
  visitedNodes: 0,
  unknownFindings: 0,
});
