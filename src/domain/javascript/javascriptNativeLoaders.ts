import * as t from "@babel/types";

import type { JavaScriptModuleOrigin } from "./javascriptSemanticIr.js";
import { electronMemberPath } from "./javascriptElectronMemberWrites.js";
import { unwrapJavaScriptExpression } from "./javascriptAstValues.js";
import {
  isUnshadowedGlobal,
  resolveSemanticBindingState,
  semanticScopeId,
  semanticStableInitializer,
  type JavaScriptSemanticAnalysisState,
  type JavaScriptSemanticBindingState,
} from "./javascriptSemanticState.js";
import type { JavaScriptNativeLoaderCall } from "./javascriptStaticAnalysisState.js";

const MODULE = /^(?:node:)?module$/u;

type Loader = JavaScriptNativeLoaderCall["loader"];

/**
 * Classify calls that load native or CommonJS modules outside a plain
 * `require`: a function created by `module.createRequire`, the `bindings` and
 * `node-gyp-build` loader packages, and `process.dlopen`. A callee is followed
 * through one stable alias, or through a parameter default value, which a
 * caller may replace.
 */
export const createNativeLoaderClassifier = (
  state: JavaScriptSemanticAnalysisState,
  moduleOrigin: (node: t.Node) => JavaScriptModuleOrigin | undefined,
) => {
  const valueLoader = (node: t.Node): Loader | undefined => {
    const expression = lastExpression(node);
    if (t.isCallExpression(expression)) {
      const origin = moduleOrigin(lastExpression(expression.callee));
      if (
        origin !== undefined &&
        MODULE.test(origin.specifier) &&
        exportPath(origin) === "createRequire"
      )
        return "create-require";
    }
    const origin = moduleOrigin(expression);
    if (origin === undefined || exportPath(origin) !== "") return undefined;
    if (origin.specifier === "bindings") return "bindings";
    if (origin.specifier === "node-gyp-build") return "node-gyp-build";
    return undefined;
  };

  const bindings = new Map<string, JavaScriptNativeLoaderCall | null>();
  const identifierLoader = (
    node: t.Identifier,
  ): JavaScriptNativeLoaderCall | undefined => {
    const binding = resolveSemanticBindingState(state, node, node.name);
    if (binding === undefined) return undefined;
    const cached = bindings.get(binding.bindingId);
    if (cached !== undefined) return cached ?? undefined;
    // A cycle through parameter defaults resolves to no loader.
    bindings.set(binding.bindingId, null);
    const result = bindingLoader(node, binding);
    bindings.set(binding.bindingId, result ?? null);
    return result;
  };

  const bindingLoader = (
    callee: t.Identifier,
    binding: JavaScriptSemanticBindingState,
  ): JavaScriptNativeLoaderCall | undefined => {
    const imported = valueLoader(callee);
    if (binding.directOrigins.length > 0)
      return imported === undefined
        ? undefined
        : { loader: imported, basis: "alias" };
    const initializer = semanticStableInitializer(binding, state);
    if (initializer !== undefined) {
      const loader =
        initializer.projection.length === 0
          ? valueLoader(initializer.node)
          : undefined;
      return loader === undefined ? undefined : { loader, basis: "alias" };
    }
    const fallback =
      binding.kind === "parameter" && binding.definitions.length === 1
        ? parameterDefault(callee, binding.scopeId, state)
        : undefined;
    const loader =
      fallback === undefined
        ? undefined
        : t.isIdentifier(fallback)
          ? identifierLoader(fallback)?.loader
          : valueLoader(fallback);
    return loader === undefined
      ? undefined
      : { loader, basis: "parameter-default" };
  };

  return (
    node: t.CallExpression | t.OptionalCallExpression,
  ): JavaScriptNativeLoaderCall | undefined => {
    const callee = lastExpression(node.callee);
    const { root, members } = electronMemberPath(callee);
    if (
      members.length === 1 &&
      members[0] === "dlopen" &&
      isUnshadowedGlobal(root, state, "process")
    )
      return { loader: "process-dlopen", basis: "direct" };
    if (!t.isIdentifier(callee)) {
      const direct = valueLoader(callee);
      return direct === undefined
        ? undefined
        : { loader: direct, basis: "direct" };
    }
    return identifierLoader(callee);
  };
};

const lastExpression = (node: t.Node): t.Node => {
  const expression = unwrapJavaScriptExpression(node).node;
  const last = t.isSequenceExpression(expression)
    ? expression.expressions.at(-1)
    : undefined;
  return last === undefined
    ? expression
    : unwrapJavaScriptExpression(last).node;
};

// ES module interop exposes a CommonJS loader as its `default` export.
const exportPath = (origin: JavaScriptModuleOrigin): string =>
  (origin.importedPath[0] === "default"
    ? origin.importedPath.slice(1)
    : origin.importedPath
  ).join(".");

const parameterDefault = (
  node: t.Identifier,
  scopeId: string,
  state: JavaScriptSemanticAnalysisState,
): t.Expression | undefined => {
  let current: t.Node | undefined = state.parentsByNode.get(node);
  while (
    current !== undefined &&
    !(t.isFunction(current) && semanticScopeId("function", current) === scopeId)
  )
    current = state.parentsByNode.get(current);
  if (current === undefined || !t.isFunction(current)) return undefined;
  for (const parameter of current.params)
    if (
      t.isAssignmentPattern(parameter) &&
      t.isIdentifier(parameter.left, { name: node.name })
    )
      return parameter.right;
  return undefined;
};
