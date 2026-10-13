import * as t from "@babel/types";

import { unwrapJavaScriptExpression } from "./javascriptAstValues.js";
import {
  resolveSemanticBindingState,
  type JavaScriptSemanticAnalysisState,
} from "./javascriptSemanticState.js";

const aliasesByState = new WeakMap<
  JavaScriptSemanticAnalysisState,
  ReadonlyMap<string, ReadonlySet<string>>
>();

/**
 * Possible direct reference aliases from the completed lexical initializer index.
 * Copies and projections are separate values. One shared component per binding
 * keeps graph construction and retained membership proportional to source size.
 */
export const javascriptBindingAliasComponents = (
  state: JavaScriptSemanticAnalysisState,
): ReadonlyMap<string, ReadonlySet<string>> => {
  const cached = aliasesByState.get(state);
  if (cached !== undefined) return cached;
  const adjacent = new Map<string, Set<string>>();
  const connect = (left: string, right: string): void => {
    const neighbors = adjacent.get(left) ?? new Set<string>();
    neighbors.add(right);
    adjacent.set(left, neighbors);
  };
  for (const binding of state.bindingsById.values()) {
    for (const initializer of binding.initializers) {
      if (
        initializer.entryBody !== undefined ||
        initializer.projection.length !== 0
      )
        continue;
      const node = unwrapJavaScriptExpression(initializer.node).node;
      if (!t.isIdentifier(node)) continue;
      const source = resolveSemanticBindingState(state, node, node.name);
      if (source === undefined) continue;
      connect(source.bindingId, binding.bindingId);
      connect(binding.bindingId, source.bindingId);
    }
  }
  const components = new Map<string, ReadonlySet<string>>();
  for (const id of state.bindingsById.keys()) {
    if (components.has(id)) continue;
    const component = new Set<string>();
    const pending = [id];
    while (pending.length > 0) {
      const next = pending.pop();
      if (next === undefined || component.has(next)) continue;
      component.add(next);
      for (const neighbor of adjacent.get(next) ?? []) pending.push(neighbor);
    }
    for (const member of component) components.set(member, component);
  }
  aliasesByState.set(state, components);
  return components;
};
