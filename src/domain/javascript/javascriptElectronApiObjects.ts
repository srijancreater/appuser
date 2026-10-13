import * as t from "@babel/types";

import type { ElectronCalleeBinding } from "./electronStaticAnalysisTypes.js";
import { electronMemberPath } from "./javascriptElectronMemberWrites.js";
import { unwrapJavaScriptExpression } from "./javascriptAstValues.js";
import {
  resolveSemanticBindingState,
  semanticStableInitializer,
  type JavaScriptSemanticAnalysisState,
} from "./javascriptSemanticState.js";
import type { ElectronApiObject } from "./javascriptStaticAnalysisState.js";

const EXPOSURES = new Set(["exposeInMainWorld", "exposeInIsolatedWorld"]);
// The same nesting bound used when collecting dotted bridge member keys.
const MAX_DEPTH = 8;

/** Whether a callee's final member names a contextBridge exposure method. */
export const isContextBridgeExposure = (
  member: string | null | undefined,
): boolean => member !== undefined && member !== null && EXPOSURES.has(member);

/**
 * Bind identifiers in contextBridge API arguments to their single stable
 * object-literal initializer, including identifiers nested as member values or
 * as branches of conditional spreads. Visible member writes to a bound object
 * are retained as a flag; writes through escaped references are not examined.
 */
export const resolveElectronApiObjects = (
  state: JavaScriptSemanticAnalysisState,
  exposures: readonly (t.CallExpression | t.OptionalCallExpression)[],
  callees: ReadonlyMap<number, ElectronCalleeBinding>,
  memberWritten: ReadonlySet<string>,
): ReadonlyMap<number, ElectronApiObject> => {
  const objects = new Map<number, ElectronApiObject>();
  const visit = (node: t.Node, depth: number): void => {
    if (depth >= MAX_DEPTH) return;
    const expression = unwrapJavaScriptExpression(node).node;
    if (t.isObjectExpression(expression)) {
      for (const property of expression.properties)
        if (t.isSpreadElement(property))
          visitBranches(property.argument, depth);
        else if (t.isObjectProperty(property)) visit(property.value, depth + 1);
      return;
    }
    if (!t.isIdentifier(expression) || objects.has(expression.start ?? -1))
      return;
    const binding = resolveSemanticBindingState(
      state,
      expression,
      expression.name,
    );
    const initializer = semanticStableInitializer(binding, state);
    const object =
      initializer?.projection.length === 0
        ? unwrapJavaScriptExpression(initializer.node).node
        : undefined;
    if (binding === undefined || !t.isObjectExpression(object)) return;
    objects.set(expression.start ?? -1, {
      object,
      memberWrites: memberWritten.has(binding.bindingId),
    });
    visit(object, depth);
  };
  const visitBranches = (node: t.Node, depth: number): void => {
    const expression = unwrapJavaScriptExpression(node).node;
    if (t.isConditionalExpression(expression)) {
      visitBranches(expression.consequent, depth);
      visitBranches(expression.alternate, depth);
    } else if (t.isLogicalExpression(expression)) {
      visitBranches(expression.left, depth);
      visitBranches(expression.right, depth);
    } else visit(expression, depth);
  };
  for (const call of exposures) {
    const { root, members } = electronMemberPath(call.callee);
    const callee = callees.get(root.start ?? -1);
    if (callee === undefined) continue;
    const path = [...callee.path, ...members.slice(callee.consumed_members)];
    if (path.length !== 2 || path[0] !== "contextBridge") continue;
    const api = call.arguments[path[1] === "exposeInIsolatedWorld" ? 2 : 1];
    if (api !== undefined && !t.isSpreadElement(api)) visit(api, 0);
  }
  return objects;
};
