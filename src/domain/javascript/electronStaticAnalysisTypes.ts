import type {
  ContentSecurityPolicyConcern,
  ContentSecurityPolicyDirective,
} from "./contentSecurityPolicy.js";
import type {
  JavaScriptSourceRange,
  JavaScriptStaticPathContext,
} from "./javascriptStaticAnalysisTypes.js";

/**
 * One inert literal, exact value derived from a constant expression, or
 * unresolved expression observed in Electron syntax.
 */
export type ElectronStaticValue =
  | {
      readonly status: "literal";
      readonly value: string | number | boolean | null;
      readonly expression: null;
    }
  | {
      readonly status: "derived";
      readonly value: string | number | boolean | null;
      readonly expression: string;
    }
  | {
      readonly status: "dynamic";
      readonly value: null;
      readonly expression: string;
    };

/** One explicitly present BrowserWindow webPreference. */
export interface ElectronWebPreference {
  readonly name: string;
  readonly value: ElectronStaticValue;
}

/** A statically resolved BrowserWindow preload declaration, or its absence. */
export type ElectronBrowserWindowPreload =
  | {
      readonly preload_path: string;
      readonly preload_resolution_context: JavaScriptStaticPathContext;
    }
  | {
      readonly preload_path: null;
      readonly preload_resolution_context: null;
    };

/** Statically visible window or view construction and preference surface. */
export type ElectronBrowserWindowFinding = ElectronBrowserWindowPreload & {
  readonly api: "BrowserWindow" | "BrowserView" | "WebContentsView";
  readonly options_status: "object-literal" | "dynamic" | "missing";
  readonly web_preferences_status: "object-literal" | "dynamic" | "missing";
  readonly web_preferences: readonly ElectronWebPreference[];
  readonly electron_identity: ElectronApiIdentity;
  readonly module_key: string | null;
  /** Recovered factory runtime; absent in older or unbundled findings. */
  readonly module_runtime?: string;
  readonly location: JavaScriptSourceRange;
};

/**
 * Literal, derived, dynamic, or unsupported contextBridge API key syntax. A
 * derived key retains the expression its exact value was folded from.
 */
export type ElectronContextBridgeApiKey =
  | { readonly api_key: string; readonly api_key_expression: null }
  | { readonly api_key: string; readonly api_key_expression: string }
  | { readonly api_key: null; readonly api_key_expression: string }
  | { readonly api_key: null; readonly api_key_expression: null };

/** One contextBridge API declaration without executing its API object. */
export type ElectronContextBridgeFinding = ElectronContextBridgeApiKey & {
  readonly resolution_basis?: "wrapper-substitution";
  readonly world: "main" | "isolated";
  readonly world_id: ElectronStaticValue | null;
  readonly api_status:
    | "object-literal"
    | "object-binding"
    | "dynamic"
    | "missing";
  readonly members: readonly string[];
  /** Keys present only in one branch of a conditional object spread. */
  readonly conditional_members: readonly string[];
  readonly unknown_members: number;
  readonly electron_identity: ElectronApiIdentity;
  readonly module_key: string | null;
  /** Recovered factory runtime; absent in older or unbundled findings. */
  readonly module_runtime?: string;
  readonly location: JavaScriptSourceRange;
};

/** Electron IPC operation identity and its semantic communication mode. */
export type ElectronIpcDescriptor =
  | {
      readonly side: "renderer";
      readonly operation:
        | "send"
        | "send-sync"
        | "post-message"
        | "send-to-host";
      readonly mode: "send";
    }
  | {
      readonly side: "renderer";
      readonly operation: "invoke";
      readonly mode: "invoke";
    }
  | {
      readonly side: "renderer" | "main";
      readonly operation: "on" | "once";
      readonly mode: "listen";
    }
  | {
      readonly side: "main";
      readonly operation: "handle" | "handle-once";
      readonly mode: "handle";
    };

type ElectronIpcHandler =
  | {
      readonly mode: "send" | "invoke";
      readonly handler_kind: null;
      readonly handler_location: null;
    }
  | {
      readonly mode: "listen" | "handle";
      readonly handler_kind: "missing";
      readonly handler_location: null;
    }
  | {
      readonly mode: "listen" | "handle";
      readonly handler_kind:
        | "inline-function"
        | "identifier"
        | "member-expression"
        | "dynamic-expression";
      readonly handler_location: JavaScriptSourceRange;
    };

interface ElectronIpcFindingContext {
  readonly electron_identity: ElectronApiIdentity;
  /** Absent on direct syntax observations; wrappers require inferred evidence. */
  readonly resolution_basis?: "wrapper-substitution";
  readonly module_key: string | null;
  /** Recovered factory runtime; absent in older or unbundled findings. */
  readonly module_runtime?: string;
  readonly location: JavaScriptSourceRange;
  /** Outer syntax invocation when a wrapper produced this underlying IPC call. */
  readonly invocation_location?: JavaScriptSourceRange;
  /**
   * Predicate conjunctions under which wrapper substitution reached this
   * operation; it occurs when any conjunction holds. Absent when it was
   * reached unconditionally. A guarded operation is never a pairing match.
   */
  readonly guard_alternatives?: readonly (readonly ElectronPathCondition[])[];
  /**
   * The underlying Electron call when it lies in a linked source; `location`
   * is then the call of this source that reached it.
   */
  readonly linked_operation?: {
    readonly source_path: string;
    readonly location: JavaScriptSourceRange;
  };
}

/**
 * A literal, derived, or dynamic IPC channel. A channel with an expression was
 * derived from that constant expression.
 */
export type ElectronIpcChannel =
  | { readonly channel: string; readonly channel_expression: null }
  | { readonly channel: string; readonly channel_expression: string }
  | { readonly channel: null; readonly channel_expression: string };

/** One statically visible Electron IPC send, invocation, listener, or handler. */
export type ElectronIpcFinding = ElectronIpcDescriptor &
  ElectronIpcHandler &
  ElectronIpcFindingContext &
  ElectronIpcChannel;

/** Static check involving an IPC sender, frame, process, URL, or origin. */
export interface ElectronSenderValidationFinding {
  readonly subject:
    | "sender-url"
    | "sender-origin"
    | "sender-frame"
    | "sender-id"
    | "frame-id"
    | "process-id";
  readonly mechanism: string;
  readonly expected: ElectronStaticValue;
  readonly enforcement: "unknown";
  readonly module_key: string | null;
  /** Recovered factory runtime; absent in older or unbundled findings. */
  readonly module_runtime?: string;
  readonly location: JavaScriptSourceRange;
}

interface ElectronUtilityProcessFindingState {
  readonly service_name: string | null;
  readonly electron_identity: ElectronApiIdentity;
  readonly module_key: string | null;
  /** Recovered factory runtime; absent in older or unbundled findings. */
  readonly module_runtime?: string;
  readonly location: JavaScriptSourceRange;
}

/** One utilityProcess.fork declaration and its statically visible entrypoint. */
export type ElectronUtilityProcessFinding = ElectronUtilityProcessFindingState &
  (
    | {
        readonly module_path: string;
        readonly module_resolution_context: JavaScriptStaticPathContext;
        readonly module_expression: null;
      }
    | {
        readonly module_path: null;
        readonly module_resolution_context: null;
        readonly module_expression: string;
      }
  );

/** JavaScript-side binding or re-export requested from one native .node addon. */
export interface ElectronNativeAddonBindingFinding {
  /** Module specifier, loader argument, or the dynamic argument expression. */
  readonly specifier: string;
  readonly specifier_status: "literal" | "dynamic";
  readonly binding_kind: "import" | "require" | "re-export" | "loader";
  /** Loader that performs the load; null for a plain import or require. */
  readonly loader:
    | "create-require"
    | "bindings"
    | "node-gyp-build"
    | "process-dlopen"
    | null;
  readonly loader_basis: "direct" | "alias" | "parameter-default" | null;
  readonly module_kind: "import" | "require";
  /** Exact requested addon member keys; namespace and dynamic access are separate. */
  readonly members: readonly string[];
  /** Omitted in legacy findings; omission means unknown, not false. */
  readonly namespace_access?: boolean;
  readonly dynamic_member_access?: boolean;
  readonly module_key: string | null;
  /** Recovered factory runtime; absent in older or unbundled findings. */
  readonly module_runtime?: string;
  readonly location: JavaScriptSourceRange;
}

/**
 * How a finding's Electron API identity was established. A module binding is
 * a proven lexical alias of the Electron module. The other bases are
 * inferences. A wrapper parameter is a parameter of a function whose same-file
 * call sites pass a proven Electron export, directly or as an object-literal
 * member. Local alternatives are a binding initialized with a fallback,
 * conditional, or object literal of which some branches prove the export.
 */
export type ElectronApiIdentity =
  | { readonly basis: "module-binding" }
  | {
      readonly basis: "wrapper-parameter";
      readonly function_name: string;
      readonly parameter: string;
      readonly parameter_index: number;
      readonly function_location: JavaScriptSourceRange;
      /** Direct calls of the function found in the same file. */
      readonly call_sites: number;
      /** False when the function is also referenced other than as a callee. */
      readonly call_sites_complete: boolean;
      /** Argument expressions, including fallback branches, that prove the export. */
      readonly electron_argument_locations: readonly JavaScriptSourceRange[];
      /** Argument expressions or branches whose value is unresolved. */
      readonly unresolved_arguments: number;
    }
  | {
      readonly basis: "local-alternatives";
      readonly binding: string;
      readonly initializer_location: JavaScriptSourceRange;
      /** Branches or members of the initializer that prove the export. */
      readonly electron_value_locations: readonly JavaScriptSourceRange[];
      readonly unresolved_values: number;
    };

/** One write to a `will-attach-webview` handler's preferences or params. */
export interface ElectronWebviewAttachWrite {
  readonly target: "web-preferences" | "params";
  readonly name: string;
  readonly operation: "assign" | "delete";
  /** Assigned value; null for a deletion. */
  readonly value: ElectronStaticValue | null;
  readonly location: JavaScriptSourceRange;
}

/**
 * One `will-attach-webview` listener. The event name is Electron-specific; the
 * receiver is not proven to be a webContents.
 */
export interface ElectronWebviewAttachFinding {
  readonly handler_kind:
    | "inline-function"
    | "identifier"
    | "member-expression"
    | "dynamic-expression"
    | "missing";
  readonly handler_location: JavaScriptSourceRange | null;
  readonly writes: readonly ElectronWebviewAttachWrite[];
  /** Static preload path written to the webview's preferences, if exact. */
  readonly preload_path: string | null;
  readonly preload_resolution_context: JavaScriptStaticPathContext | null;
  /** Writes with computed keys, or handler bodies that were not examined. */
  readonly unknown_writes: number;
  readonly module_key: string | null;
  /** Recovered factory runtime; absent in older or unbundled findings. */
  readonly module_runtime?: string;
  readonly location: JavaScriptSourceRange;
}

/**
 * One Content-Security-Policy recovered from JavaScript or HTML. `policy`
 * keeps runtime parts as `${…}`; directives with such parts are not judged.
 */
export interface ElectronContentSecurityPolicyFinding {
  readonly mechanism:
    | "header-property"
    | "directive-list"
    | "string-literal"
    | "html-meta-string"
    | "html-meta";
  /** Lower-case header name, when the policy is a header or meta value. */
  readonly header: string | null;
  readonly policy: string | null;
  /** The value expression when no policy text is static. */
  readonly policy_expression: string | null;
  readonly directives: readonly ContentSecurityPolicyDirective[];
  readonly concerns: readonly ContentSecurityPolicyConcern[];
  readonly dynamic_parts: number;
  readonly module_key: string | null;
  /** Recovered factory runtime; absent in older or unbundled findings. */
  readonly module_runtime?: string;
  readonly location: JavaScriptSourceRange;
}

/** Resolved Electron identity of one call or construction callee root. */
export interface ElectronCalleeBinding {
  /** Electron export path of the root after `consumed_members` callee members. */
  readonly path: readonly string[];
  readonly consumed_members: number;
  readonly identity: ElectronApiIdentity;
}

/** All Electron-specific facts collected during one shared AST traversal. */
export interface ElectronStaticFindings {
  readonly browser_windows: readonly ElectronBrowserWindowFinding[];
  readonly context_bridge_apis: readonly ElectronContextBridgeFinding[];
  readonly ipc: readonly ElectronIpcFinding[];
  readonly sender_validations: readonly ElectronSenderValidationFinding[];
  readonly utility_processes: readonly ElectronUtilityProcessFinding[];
  readonly native_addon_bindings: readonly ElectronNativeAddonBindingFinding[];
  readonly webview_attachments: readonly ElectronWebviewAttachFinding[];
  readonly content_security_policies: readonly ElectronContentSecurityPolicyFinding[];
  /** Source-bound candidate paths through bundled exports and IPC closures. */
  readonly call_paths?: readonly ElectronCallPath[];
}

export interface ElectronCallPathStep {
  readonly kind:
    | "exposure"
    | "factory"
    | "function"
    | "call"
    | "ipc"
    | "terminal";
  readonly label: string;
  readonly location: JavaScriptSourceRange;
  readonly module_key: string | null;
  readonly module_runtime: string | null;
  /** Exact linked source identity; both fields are absent for this source. */
  readonly source_path?: string;
  readonly source_sha256?: string;
}

/** One unresolved branch predicate on a substituted path. */
export interface ElectronPathCondition {
  readonly expression: string;
  readonly location: JavaScriptSourceRange;
  /** Artifact path of a linked source holding the predicate; absent for this source. */
  readonly source_path?: string;
}

/** A statically substituted candidate, never a runtime reachability claim. */
export interface ElectronCallPath {
  readonly entry_kind: "bridge-member" | "ipc-handler";
  readonly entry: string;
  readonly channel: string | null;
  readonly terminal: string;
  readonly resolution: "candidate";
  readonly steps: readonly ElectronCallPathStep[];
  readonly conditions: readonly ElectronPathCondition[];
}

/** Number of Electron findings, counted once for limits and limitations. */
export const electronStaticFindingCount = (
  electron: ElectronStaticFindings,
): number =>
  electron.browser_windows.length +
  electron.context_bridge_apis.length +
  electron.ipc.length +
  electron.sender_validations.length +
  electron.utility_processes.length +
  electron.native_addon_bindings.length +
  electron.webview_attachments.length +
  electron.content_security_policies.length;
