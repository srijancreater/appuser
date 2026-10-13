import * as t from "@babel/types";

import type {
  ElectronWebviewAttachFinding,
  ElectronWebviewAttachWrite,
} from "./electronStaticAnalysisTypes.js";
import {
  electronStaticValue,
  handlerKind,
} from "./electronStaticAnalysisValues.js";
import { semanticStaticPropertyKey } from "./javascriptAstValues.js";
import { addLocatedFinding } from "./javascriptStaticAnalysisFindings.js";
import {
  argumentNode,
  range,
  staticPath,
  staticPathResolutionContext,
} from "./javascriptStaticAnalysisHelpers.js";
import { childNodes } from "./javascriptSemanticTraversal.js";
import type { JavaScriptFindingContext } from "./javascriptStaticAnalysisState.js";

const LISTENERS = new Set(["on", "once", "addListener", "prependListener"]);

/** Inspect `will-attach-webview` listeners and their preference writes. */
export const inspectElectronWebviewNode = (
  node: t.Node,
  context: JavaScriptFindingContext,
): void => {
  if (!t.isCallExpression(node) && !t.isOptionalCallExpression(node)) return;
  const { callee } = node;
  if (!t.isMemberExpression(callee) && !t.isOptionalMemberExpression(callee))
    return;
  const method = semanticStaticPropertyKey(callee.property, callee.computed);
  const event = argumentNode(node.arguments[0]);
  if (
    method === null ||
    !LISTENERS.has(method) ||
    !t.isStringLiteral(event, { value: "will-attach-webview" })
  )
    return;
  const handler = argumentNode(node.arguments[1]);
  const kind = handler === undefined ? "missing" : handlerKind(handler);
  const examined =
    kind === "inline-function" && t.isFunction(handler)
      ? collectWrites(handler, context)
      : { writes: [], unknown: 1, preload: undefined };
  context.accumulator.unknownFindings += examined.unknown;
  const preload = examined.preload;
  const finding: ElectronWebviewAttachFinding = {
    handler_kind: kind,
    handler_location: handler === undefined ? null : range(handler),
    writes: examined.writes,
    preload_path: preload === undefined ? null : (staticPath(preload) ?? null),
    preload_resolution_context:
      preload === undefined || staticPath(preload) === undefined
        ? null
        : staticPathResolutionContext(preload),
    unknown_writes: examined.unknown,
    module_key: null,
    location: range(node),
  };
  addLocatedFinding(context, {
    collection: context.accumulator.webviewAttachments,
    key: "electron-webview-attach",
    node,
    value: finding,
  });
};

// Writes through the listener's second (webPreferences) and third (params)
// parameters, resolved by their parsed lexical owners across nested scopes.
const collectWrites = (
  handler: t.Function,
  context: JavaScriptFindingContext,
): {
  readonly writes: readonly ElectronWebviewAttachWrite[];
  readonly unknown: number;
  /** The last preload value written in source order. */
  readonly preload: t.Expression | undefined;
} => {
  const names = new Map<string, ElectronWebviewAttachWrite["target"]>();
  const [, preferences, params] = handler.params;
  const bindingId = context.electron?.bindingId;
  if (bindingId === undefined)
    return { writes: [], unknown: 1, preload: undefined };
  if (t.isIdentifier(preferences)) {
    const id = bindingId(preferences);
    if (id !== undefined) names.set(id, "web-preferences");
  }
  if (t.isIdentifier(params)) {
    const id = bindingId(params);
    if (id !== undefined) names.set(id, "params");
  }
  const writes: ElectronWebviewAttachWrite[] = [];
  let unknown = 0;
  let preload:
    | { readonly start: number; readonly value: t.Expression | undefined }
    | undefined;
  const pending: t.Node[] = [handler.body];
  while (pending.length > 0) {
    const node = pending.pop();
    if (node === undefined) break;
    const write = writeTarget(node);
    if (write !== undefined && t.isIdentifier(write.member.object)) {
      const id = bindingId(write.member.object);
      const target = id === undefined ? undefined : names.get(id);
      if (target !== undefined) {
        const name = semanticStaticPropertyKey(
          write.member.property,
          write.member.computed,
        );
        if (
          target === "web-preferences" &&
          name === "preload" &&
          (node.start ?? -1) >= (preload?.start ?? -1)
        )
          preload = { start: node.start ?? -1, value: write.value };
        if (name === null) unknown += 1;
        else
          writes.push({
            target,
            name,
            operation: write.operation,
            value: writtenValue(name, write.value, context),
            location: range(node),
          });
      }
    }
    pending.push(...childNodes(node).toReversed());
  }
  writes.sort(
    (left, right) =>
      left.location.start.line - right.location.start.line ||
      left.location.start.column - right.location.start.column,
  );
  return { writes, unknown, preload: preload?.value };
};

const writtenValue = (
  name: string,
  value: t.Expression | undefined,
  context: JavaScriptFindingContext,
): ElectronWebviewAttachWrite["value"] => {
  if (value === undefined) return null;
  const path = name === "preload" ? staticPath(value) : undefined;
  return path === undefined
    ? electronStaticValue(context, value)
    : { status: "literal", value: path, expression: null };
};

const writeTarget = (
  node: t.Node,
):
  | {
      readonly member: t.MemberExpression;
      readonly operation: ElectronWebviewAttachWrite["operation"];
      readonly value: t.Expression | undefined;
    }
  | undefined => {
  if (
    t.isAssignmentExpression(node, { operator: "=" }) &&
    t.isMemberExpression(node.left)
  )
    return { member: node.left, operation: "assign", value: node.right };
  if (
    t.isUnaryExpression(node, { operator: "delete" }) &&
    t.isMemberExpression(node.argument)
  )
    return { member: node.argument, operation: "delete", value: undefined };
  return undefined;
};
