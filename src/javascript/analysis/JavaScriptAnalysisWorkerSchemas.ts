import { z } from "zod";
import { digestSchema } from "../../domain/digests.js";
import type { JavaScriptStaticAnalysis } from "../../domain/javascript/javascriptStaticAnalysisTypes.js";
import type {
  JavaScriptSemanticProperty,
  JavaScriptSemanticValue,
} from "../../domain/javascript/javascriptSemanticValueTypes.js";
import {
  javaScriptSemanticNodeSchema,
  javaScriptSemanticRelationSchema,
  javaScriptSemanticUnknownSchema,
  javaScriptSemanticFingerprintSchema,
  javaScriptSemanticEvidenceContextSchema,
  javaScriptSemanticFileProjectionCoverageSchema,
} from "../../domain/javascript/javascriptSemanticGraphSchemas.js";

const range =
  javaScriptSemanticNodeSchema.shape.identity.shape.source_range.unwrap();
const count = z.number().int().nonnegative();
const strings = z.array(z.string());
const pathContext = z.enum(["module-specifier", "filesystem-expression"]);
const findingContext = {
  module_key: z.string().nullable(),
  module_runtime: z.string().optional(),
  location: range,
};
const withRuntime = <
  Value extends {
    module_runtime?: string | undefined;
    resolution_basis?: "wrapper-substitution" | undefined;
  },
>(
  value: Value,
) => {
  const { module_runtime, resolution_basis, ...rest } = value;
  return {
    ...rest,
    ...(module_runtime === undefined ? {} : { module_runtime }),
    ...(resolution_basis === undefined ? {} : { resolution_basis }),
  };
};
const staticValue = z.discriminatedUnion("status", [
  z.strictObject({
    status: z.literal("literal"),
    value: z.union([z.string(), z.number(), z.boolean(), z.null()]),
    expression: z.null(),
  }),
  z.strictObject({
    status: z.literal("derived"),
    value: z.union([z.string(), z.number(), z.boolean(), z.null()]),
    expression: z.string(),
  }),
  z.strictObject({
    status: z.literal("dynamic"),
    value: z.null(),
    expression: z.string(),
  }),
]);
const electronIdentity = z.discriminatedUnion("basis", [
  z.strictObject({ basis: z.literal("module-binding") }),
  z.strictObject({
    basis: z.literal("wrapper-parameter"),
    function_name: z.string(),
    parameter: z.string(),
    parameter_index: count,
    function_location: range,
    call_sites: count,
    call_sites_complete: z.boolean(),
    electron_argument_locations: z.array(range),
    unresolved_arguments: count,
  }),
  z.strictObject({
    basis: z.literal("local-alternatives"),
    binding: z.string(),
    initializer_location: range,
    electron_value_locations: z.array(range),
    unresolved_values: count,
  }),
]);
const electronFindingContext = {
  ...findingContext,
  electron_identity: electronIdentity,
};
const pathCondition = z.strictObject({
  expression: z.string(),
  location: range,
  source_path: z.string().exactOptional(),
});
const nullHandler = { handler_kind: z.null(), handler_location: z.null() };
const missingHandler = {
  handler_kind: z.literal("missing"),
  handler_location: z.null(),
};
const locatedHandler = {
  handler_kind: z.enum([
    "inline-function",
    "identifier",
    "member-expression",
    "dynamic-expression",
  ]),
  handler_location: range,
};
const ipcChannel = <Shape extends z.ZodRawShape>(shape: Shape) =>
  z.union([
    z.strictObject({
      ...electronFindingContext,
      invocation_location: range.optional(),
      guard_alternatives: z.array(z.array(pathCondition)).optional(),
      linked_operation: z
        .strictObject({ source_path: z.string(), location: range })
        .optional(),
      resolution_basis: z.literal("wrapper-substitution").optional(),
      ...shape,
      channel: z.string(),
      channel_expression: z.null(),
    }),
    z.strictObject({
      ...electronFindingContext,
      invocation_location: range.optional(),
      guard_alternatives: z.array(z.array(pathCondition)).optional(),
      linked_operation: z
        .strictObject({ source_path: z.string(), location: range })
        .optional(),
      resolution_basis: z.literal("wrapper-substitution").optional(),
      ...shape,
      channel: z.string(),
      channel_expression: z.string(),
    }),
    z.strictObject({
      ...electronFindingContext,
      invocation_location: range.optional(),
      guard_alternatives: z.array(z.array(pathCondition)).optional(),
      linked_operation: z
        .strictObject({ source_path: z.string(), location: range })
        .optional(),
      resolution_basis: z.literal("wrapper-substitution").optional(),
      ...shape,
      channel: z.null(),
      channel_expression: z.string(),
    }),
  ]);
const ipc = z
  .union([
    ipcChannel({
      side: z.literal("renderer"),
      operation: z.enum(["send", "send-sync", "post-message", "send-to-host"]),
      mode: z.literal("send"),
      ...nullHandler,
    }),
    ipcChannel({
      side: z.literal("renderer"),
      operation: z.literal("invoke"),
      mode: z.literal("invoke"),
      ...nullHandler,
    }),
    ipcChannel({
      side: z.enum(["renderer", "main"]),
      operation: z.enum(["on", "once"]),
      mode: z.literal("listen"),
      ...missingHandler,
    }),
    ipcChannel({
      side: z.enum(["renderer", "main"]),
      operation: z.enum(["on", "once"]),
      mode: z.literal("listen"),
      ...locatedHandler,
    }),
    ipcChannel({
      side: z.literal("main"),
      operation: z.enum(["handle", "handle-once"]),
      mode: z.literal("handle"),
      ...missingHandler,
    }),
    ipcChannel({
      side: z.literal("main"),
      operation: z.enum(["handle", "handle-once"]),
      mode: z.literal("handle"),
      ...locatedHandler,
    }),
  ])
  .transform((value) => {
    const {
      module_runtime,
      resolution_basis,
      invocation_location,
      guard_alternatives,
      linked_operation,
      ...rest
    } = value;
    return {
      ...rest,
      ...(module_runtime === undefined ? {} : { module_runtime }),
      ...(resolution_basis === undefined ? {} : { resolution_basis }),
      ...(invocation_location === undefined ? {} : { invocation_location }),
      ...(guard_alternatives === undefined ? {} : { guard_alternatives }),
      ...(linked_operation === undefined ? {} : { linked_operation }),
    };
  });
const windowShape = {
  ...electronFindingContext,
  api: z.enum(["BrowserWindow", "BrowserView", "WebContentsView"]),
  options_status: z.enum(["object-literal", "dynamic", "missing"]),
  web_preferences_status: z.enum(["object-literal", "dynamic", "missing"]),
  web_preferences: z.array(
    z.strictObject({ name: z.string(), value: staticValue }),
  ),
};
const bridgeShape = {
  resolution_basis: z.literal("wrapper-substitution").optional(),
  ...electronFindingContext,
  world: z.enum(["main", "isolated"]),
  world_id: staticValue.nullable(),
  api_status: z.enum([
    "object-literal",
    "object-binding",
    "dynamic",
    "missing",
  ]),
  members: strings,
  conditional_members: strings,
  unknown_members: count,
};
const utilityShape = {
  ...electronFindingContext,
  service_name: z.string().nullable(),
};
const electron = z
  .strictObject({
    call_paths: z
      .array(
        z.strictObject({
          entry_kind: z.enum(["bridge-member", "ipc-handler"]),
          entry: z.string(),
          channel: z.string().nullable(),
          terminal: z.string(),
          resolution: z.literal("candidate"),
          steps: z.array(
            z.strictObject({
              kind: z.enum([
                "exposure",
                "factory",
                "function",
                "call",
                "ipc",
                "terminal",
              ]),
              label: z.string(),
              location: range,
              module_key: z.string().nullable(),
              module_runtime: z.string().nullable(),
              source_path: z.string().exactOptional(),
              source_sha256: z
                .string()
                .regex(/^[a-f0-9]{64}$/u)
                .exactOptional(),
            }),
          ),
          conditions: z.array(pathCondition),
        }),
      )
      .optional(),
    browser_windows: z.array(
      z.union([
        z
          .strictObject({
            ...windowShape,
            preload_path: z.string(),
            preload_resolution_context: pathContext,
          })
          .transform(withRuntime),
        z
          .strictObject({
            ...windowShape,
            preload_path: z.null(),
            preload_resolution_context: z.null(),
          })
          .transform(withRuntime),
      ]),
    ),
    context_bridge_apis: z.array(
      z.union([
        z
          .strictObject({
            ...bridgeShape,
            api_key: z.string(),
            api_key_expression: z.null(),
          })
          .transform(withRuntime),
        z
          .strictObject({
            ...bridgeShape,
            api_key: z.string(),
            api_key_expression: z.string(),
          })
          .transform(withRuntime),
        z
          .strictObject({
            ...bridgeShape,
            api_key: z.null(),
            api_key_expression: z.string(),
          })
          .transform(withRuntime),
        z
          .strictObject({
            ...bridgeShape,
            api_key: z.null(),
            api_key_expression: z.null(),
          })
          .transform(withRuntime),
      ]),
    ),
    ipc: z.array(ipc),
    sender_validations: z.array(
      z.strictObject({
        ...findingContext,
        subject: z.enum([
          "sender-url",
          "sender-origin",
          "sender-frame",
          "sender-id",
          "frame-id",
          "process-id",
        ]),
        mechanism: z.string(),
        expected: staticValue,
        enforcement: z.literal("unknown"),
      }),
    ),
    utility_processes: z.array(
      z.union([
        z
          .strictObject({
            ...utilityShape,
            module_path: z.string(),
            module_resolution_context: pathContext,
            module_expression: z.null(),
          })
          .transform(withRuntime),
        z
          .strictObject({
            ...utilityShape,
            module_path: z.null(),
            module_resolution_context: z.null(),
            module_expression: z.string(),
          })
          .transform(withRuntime),
      ]),
    ),
    native_addon_bindings: z.array(
      z.strictObject({
        ...findingContext,
        specifier: z.string(),
        specifier_status: z.enum(["literal", "dynamic"]),
        binding_kind: z.enum(["import", "require", "re-export", "loader"]),
        loader: z
          .enum([
            "create-require",
            "bindings",
            "node-gyp-build",
            "process-dlopen",
          ])
          .nullable(),
        loader_basis: z
          .enum(["direct", "alias", "parameter-default"])
          .nullable(),
        module_kind: z.enum(["import", "require"]),
        members: strings,
        namespace_access: z.boolean().optional(),
        dynamic_member_access: z.boolean().optional(),
      }),
    ),
    webview_attachments: z.array(
      z
        .strictObject({
          ...findingContext,
          handler_kind: z.enum([
            "inline-function",
            "identifier",
            "member-expression",
            "dynamic-expression",
            "missing",
          ]),
          handler_location: range.nullable(),
          writes: z.array(
            z.strictObject({
              target: z.enum(["web-preferences", "params"]),
              name: z.string(),
              operation: z.enum(["assign", "delete"]),
              value: staticValue.nullable(),
              location: range,
            }),
          ),
          preload_path: z.string().nullable(),
          preload_resolution_context: pathContext.nullable(),
          unknown_writes: count,
        })
        .transform(withRuntime),
    ),
    content_security_policies: z.array(
      z
        .strictObject({
          ...findingContext,
          mechanism: z.enum([
            "header-property",
            "directive-list",
            "string-literal",
            "html-meta-string",
            "html-meta",
          ]),
          header: z.string().nullable(),
          policy: z.string().nullable(),
          policy_expression: z.string().nullable(),
          directives: z.array(
            z.strictObject({ name: z.string(), sources: strings }),
          ),
          concerns: z.array(
            z.strictObject({
              directive: z.string(),
              source: z.string().nullable(),
              reason: z.string(),
            }),
          ),
          dynamic_parts: count,
        })
        .transform(withRuntime),
    ),
  })
  .transform(({ call_paths, ...rest }) => ({
    ...rest,
    ...(call_paths === undefined ? {} : { call_paths }),
  }));
const referenceShape = {
  ...findingContext,
  kind: z.enum([
    "static-import",
    "dynamic-import",
    "require",
    "worker",
    "service-worker",
  ]),
};

/** Exact producer facts recoverable before a later semantic worker failure. */
export const javaScriptWorkerStaticAnalysisSchema = z
  .strictObject({
    parse_status: z.enum(["complete", "partial", "failed"]),
    parse_error_count: count,
    visited_ast_nodes: count,
    references: z.array(
      z.union([
        z
          .strictObject({
            ...referenceShape,
            specifier: z.string(),
            expression: z.null(),
          })
          .transform(withRuntime),
        z
          .strictObject({
            ...referenceShape,
            specifier: z.null(),
            expression: z.string(),
          })
          .transform(withRuntime),
      ]),
    ),
    endpoints: z.array(
      z.strictObject({
        ...findingContext,
        kind: z.enum(["route", "network", "data"]),
        value: z.string(),
        expression: z.string().nullable(),
        mechanism: z.string(),
        property_path: strings.nullable(),
      }),
    ),
    storage: z.array(
      z.strictObject({
        ...findingContext,
        kind: z.enum([
          "local-storage",
          "session-storage",
          "indexed-db",
          "cache-storage",
          "sqlite",
        ]),
        name: z.string().nullable(),
        mechanism: z.string(),
      }),
    ),
    bundler_registrations: z.array(
      z.strictObject({
        bundler: z.enum(["webpack", "rspack", "esbuild"]),
        runtime: z.string(),
        chunk_keys: strings,
        unknown_chunk_keys: count,
        runtime_require_name: z.string().nullable(),
        runtime_module_cache_status: z.enum(["observed", "not-observed"]),
        entry_module_keys: strings,
        unknown_entry_module_keys: count,
        async_chunk_keys: strings,
        unknown_async_chunk_keys: count,
        modules: z.array(
          z.strictObject({
            module_key: z.string(),
            factory_require_name: z.string().nullable(),
            source_sha256: digestSchema,
            exports: strings,
            location: range,
            structural_fingerprint_sha256: digestSchema,
            structural_fingerprint_algorithm: z.literal("babel-ast-v1"),
          }),
        ),
        location: range,
      }),
    ),
    role_paths: z.array(
      z.strictObject({
        ...findingContext,
        role: z.enum(["preload", "renderer"]),
        path: z.string(),
        resolution_context: pathContext,
        mechanism: z.string(),
      }),
    ),
    source_map_urls: z.array(
      z.strictObject({ declared_url: z.string(), location: range }),
    ),
    vendors: strings,
    electron,
    constant_folding: z.discriminatedUnion("status", [
      z.strictObject({ status: z.literal("available") }),
      z.strictObject({ status: z.literal("unavailable"), reason: z.string() }),
    ]),
    limitations: strings,
  })
  .transform((analysis) => ({
    ...analysis,
    endpoints: analysis.endpoints.map(withRuntime),
    storage: analysis.storage.map(withRuntime),
    role_paths: analysis.role_paths.map(withRuntime),
    electron: {
      ...analysis.electron,
      sender_validations: analysis.electron.sender_validations.map(withRuntime),
      native_addon_bindings: analysis.electron.native_addon_bindings.map(
        (value) => {
          const { namespace_access, dynamic_member_access, ...rest } =
            withRuntime(value);
          return {
            ...rest,
            ...(namespace_access === undefined ? {} : { namespace_access }),
            ...(dynamic_member_access === undefined
              ? {}
              : { dynamic_member_access }),
          };
        },
      ),
    },
  })) satisfies z.ZodType<JavaScriptStaticAnalysis>;

const resourceLimit = z.enum([
  "primitive-candidates",
  "primitive-bytes",
  "expression-depth",
]);
const primitive = z.union([z.string(), z.number(), z.boolean(), z.null()]);
const property: z.ZodType<JavaScriptSemanticProperty> = z.lazy(() =>
  z.strictObject({
    name: z.string(),
    value: semanticValue,
    presence: z.enum(["present", "absent", "unknown-coverage"]),
  }),
);
const semanticValue: z.ZodType<JavaScriptSemanticValue> = z.lazy(() =>
  z
    .discriminatedUnion("status", [
      z.strictObject({ status: z.literal("literal"), value: primitive }),
      z.strictObject({
        status: z.literal("union"),
        values: z.array(primitive),
      }),
      z.discriminatedUnion("unknownProperties", [
        z.strictObject({
          status: z.literal("object"),
          properties: z.array(property),
          unknownProperties: z.literal(false),
          omittedProperties: z.literal(0),
        }),
        z.strictObject({
          status: z.literal("object"),
          properties: z.array(property),
          unknownProperties: z.literal(true),
          omittedProperties: count.nullable(),
        }),
      ]),
      z.discriminatedUnion("unknownItems", [
        z.strictObject({
          status: z.literal("array"),
          items: z.array(property),
          unknownItems: z.literal(false),
          omittedItems: z.literal(0),
        }),
        z.strictObject({
          status: z.literal("array"),
          items: z.array(property),
          unknownItems: z.literal(true),
          omittedItems: count.nullable(),
        }),
      ]),
      z.strictObject({
        status: z.enum(["unknown", "ambiguous", "cycle"]),
        reason: z.string(),
        resourceLimit: resourceLimit.optional(),
      }),
    ])
    .transform((value) => {
      if (
        value.status === "literal" ||
        value.status === "union" ||
        value.status === "object" ||
        value.status === "array"
      )
        return value;
      const { resourceLimit: limit, ...rest } = value;
      return {
        ...rest,
        ...(limit === undefined ? {} : { resourceLimit: limit }),
      };
    }),
);
const origin = z
  .strictObject({
    specifier: z.string(),
    importedPath: strings,
    resolutionMode: z
      .enum(["import", "require", "compiler-dependent"])
      .optional(),
  })
  .transform(({ resolutionMode, ...rest }) => ({
    ...rest,
    ...(resolutionMode === undefined ? {} : { resolutionMode }),
  }));
const provenance = z.discriminatedUnion("status", [
  z.strictObject({
    status: z.literal("module"),
    origins: z.tuple([origin]),
    reason: z.null(),
  }),
  z.strictObject({
    status: z.literal("local"),
    origins: z.tuple([]),
    reason: z.null(),
  }),
  z.strictObject({
    status: z.literal("ambiguous"),
    origins: z.array(origin),
    reason: z.string(),
  }),
  z.strictObject({
    status: z.enum(["unknown", "cycle"]),
    origins: z.tuple([]),
    reason: z.string(),
  }),
]);
const coverage = z
  .discriminatedUnion("status", [
    z.strictObject({
      status: z.literal("complete"),
      omittedCount: z.literal(0),
      resourceLimits: z.array(resourceLimit).optional(),
    }),
    z.strictObject({
      status: z.literal("partial"),
      omittedCount: z.union([z.literal(0), z.null()]),
      resourceLimits: z.array(resourceLimit).optional(),
    }),
    z.strictObject({
      status: z.literal("failed"),
      omittedCount: z.null(),
      resourceLimits: z.array(resourceLimit).optional(),
    }),
  ])
  .transform((value) => {
    const { resourceLimits, ...rest } = value;
    return {
      ...rest,
      ...(resourceLimits === undefined ? {} : { resourceLimits }),
    };
  });
const moduleLink = z
  .strictObject({
    resolutionMode: z
      .enum(["import", "require", "compiler-dependent"])
      .optional(),
    kind: z.enum([
      "import",
      "type-import",
      "require",
      "export",
      "re-export",
      "commonjs-export",
    ]),
    specifier: z.string().nullable(),
    importedName: z.string().nullable(),
    localName: z.string().nullable(),
    exportedName: z.string().nullable(),
    callableId: z.string().nullable(),
    location: range,
  })
  .transform(({ resolutionMode, ...rest }) => ({
    ...rest,
    ...(resolutionMode === undefined ? {} : { resolutionMode }),
  }));
const definitionKind = z.enum([
  "import",
  "variable",
  "parameter",
  "function",
  "class",
  "catch",
  "assignment",
]);
const scope = z.strictObject({
  scopeId: z.string(),
  parentScopeId: z.string().nullable(),
  kind: z.enum([
    "program",
    "function",
    "block",
    "static-block",
    "class",
    "catch",
  ]),
  location: range,
  bindingsComplete: z.boolean(),
  bindingIds: strings,
});
const binding = z.strictObject({
  bindingId: z.string(),
  scopeId: z.string(),
  name: z.string(),
  kind: definitionKind,
  mutable: z.boolean(),
  definitions: z.array(
    z.strictObject({ kind: definitionKind, location: range }),
  ),
  value: semanticValue,
  provenance,
});
const callable = z.strictObject({
  callableId: z.string(),
  kind: z.enum(["function", "class", "method"]),
  name: z.string().nullable(),
  containerScopeId: z.string(),
  bodyScopeId: z.string().nullable(),
  location: range,
  returnSites: z.array(
    z.strictObject({
      returnSiteId: z.string(),
      location: range,
      identityReferenceLocation: range.nullable(),
      value: semanticValue,
    }),
  ),
  returnCoverage: z.strictObject({
    retainedCount: count,
    status: z.enum(["complete", "partial"]),
    omittedCount: z.union([z.literal(0), z.null()]),
  }),
});

/** Validate each transferred graph fact independently of its emitting realm. */
export const javaScriptWorkerGraphRecordSchema = z.discriminatedUnion("kind", [
  z.strictObject({
    kind: z.literal("evidence-context"),
    value: javaScriptSemanticEvidenceContextSchema,
  }),
  z.strictObject({
    kind: z.literal("node"),
    value: javaScriptSemanticNodeSchema,
  }),
  z.strictObject({
    kind: z.literal("relation"),
    value: javaScriptSemanticRelationSchema,
  }),
  z.strictObject({
    kind: z.literal("unknown"),
    value: javaScriptSemanticUnknownSchema,
  }),
  z.strictObject({
    kind: z.literal("fingerprint"),
    value: javaScriptSemanticFingerprintSchema,
  }),
]);

/** Portable per-file header, before any graph binding or immutable proof. */
export const javaScriptWorkerProjectionHeaderSchema = z.strictObject({
  roots: z.array(javaScriptSemanticNodeSchema.shape.node_id),
  coverage: javaScriptSemanticFileProjectionCoverageSchema,
});

/** Module facts are transferred individually to avoid a whole-IR JSON string. */
export const javaScriptWorkerModuleRecordSchema = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("scope"), value: scope }),
  z.strictObject({ kind: z.literal("binding"), value: binding }),
  z.strictObject({ kind: z.literal("callable"), value: callable }),
  z.strictObject({ kind: z.literal("module-link"), value: moduleLink }),
]);

/** Coverage and limitations are independent of module collection sizes. */
export const javaScriptWorkerModuleHeaderSchema = z.strictObject({
  coverage,
  limitations: strings,
});
