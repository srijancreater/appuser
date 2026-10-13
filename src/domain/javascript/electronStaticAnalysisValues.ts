import * as t from "@babel/types";

import {
  compositeKey,
  compareUnicodeCodePoints,
} from "../unicodeCodePointOrder.js";
import type {
  ElectronApiIdentity,
  ElectronStaticValue,
} from "./electronStaticAnalysisTypes.js";
import {
  semanticStaticPropertyKey,
  semanticStaticPropertyName,
  unwrapJavaScriptExpression,
} from "./javascriptAstValues.js";
import { sourceSlice } from "./javascriptStaticAnalysisHelpers.js";
import type {
  ElectronApiObject,
  JavaScriptFindingContext,
} from "./javascriptStaticAnalysisState.js";

/** Resolve a callee only when its root has a classified Electron identity. */
export const electronCallee = (
  callee: t.Node,
  context: JavaScriptFindingContext,
):
  | {
      readonly path: readonly string[];
      readonly identity: ElectronApiIdentity;
    }
  | undefined => {
  const members: string[] = [];
  let root = callee;
  while (t.isMemberExpression(root) || t.isOptionalMemberExpression(root)) {
    const member = semanticStaticPropertyName(root.property, root.computed);
    if (member === "" || !t.isNode(root.object)) return undefined;
    members.push(member);
    root = root.object;
  }
  const binding = context.electron?.callees.get(root.start ?? -1);
  return binding === undefined
    ? undefined
    : {
        path: [
          ...binding.path,
          ...members.toReversed().slice(binding.consumed_members),
        ],
        identity: binding.identity,
      };
};

/** Preserve one literal or derived value, or the exact inert expression. */
export const electronStaticValue = (
  context: JavaScriptFindingContext,
  node: t.Node | null | undefined,
): ElectronStaticValue => {
  const constant = context.constants(node);
  if (constant.status === "literal")
    return { status: "literal", value: constant.value, expression: null };
  const expression = boundedExpression(context.source, node);
  return constant.status === "derived"
    ? { status: "derived", value: constant.value, expression }
    : { status: "dynamic", value: null, expression };
};

/** Return an actionable expression without evaluating it. */
export const boundedExpression = (
  source: string,
  node: t.Node | null | undefined,
): string => {
  if (node === null || node === undefined) return "[missing-expression]";
  const expression = sourceSlice(source, node).trim();
  return expression === "" ? `[${node.type}]` : expression;
};

/** Find the effective explicit property, preserving unresolved overrides. */
export const objectProperty = (
  object: t.Node | undefined,
  name: string,
):
  | { readonly status: "missing" | "dynamic" }
  | { readonly status: "explicit"; readonly property: t.ObjectProperty } => {
  if (object === undefined) return { status: "missing" };
  if (!t.isObjectExpression(object)) return { status: "dynamic" };
  for (const property of object.properties.toReversed()) {
    if (t.isSpreadElement(property)) return { status: "dynamic" };
    const key = semanticStaticPropertyName(property.key, property.computed);
    if (key === "" && !t.isStringLiteral(property.key))
      return { status: "dynamic" };
    if (key !== name) continue;
    return t.isObjectProperty(property)
      ? { status: "explicit", property }
      : { status: "dynamic" };
  }
  return { status: "missing" };
};

type PresentHandlerKind =
  | "inline-function"
  | "identifier"
  | "member-expression"
  | "dynamic-expression";

/** Classify a handler argument while retaining its exact source range. */
export function handlerKind(node: t.Node): PresentHandlerKind;
export function handlerKind(node: null | undefined): "missing";
export function handlerKind(
  node: t.Node | null | undefined,
): PresentHandlerKind | "missing" {
  if (node === null || node === undefined) return "missing";
  if (
    t.isArrowFunctionExpression(node) ||
    t.isFunctionExpression(node) ||
    t.isFunctionDeclaration(node)
  )
    return "inline-function";
  if (t.isIdentifier(node)) return "identifier";
  if (t.isMemberExpression(node) || t.isOptionalMemberExpression(node))
    return "member-expression";
  return "dynamic-expression";
}

/** Statically visible dotted keys of one contextBridge API argument. */
export interface ContextBridgeMembers {
  readonly status: "object-literal" | "object-binding" | "dynamic" | "missing";
  readonly members: readonly string[];
  /** Keys present only in one branch of a conditional object spread. */
  readonly conditional_members: readonly string[];
  readonly unknown: number;
}

/**
 * Collect keys from an object literal or an identifier bound to one, following
 * member values that are bound identifiers. A visible member write to a bound
 * object adds one unknown, since its added keys are not enumerated.
 */
export const collectContextBridgeMembers = (
  node: t.Node | null | undefined,
  objects: ReadonlyMap<number, ElectronApiObject> | undefined,
): ContextBridgeMembers => {
  if (node === null || node === undefined)
    return {
      status: "missing",
      members: [],
      conditional_members: [],
      unknown: 0,
    };
  const state: MemberState = {
    members: new Map(),
    expanded: new Set(),
    unknown: 0,
    objects: objects ?? new Map(),
  };
  const root = boundObject(node, state);
  if (root === undefined)
    return {
      status: "dynamic",
      members: [],
      conditional_members: [],
      unknown: 1,
    };
  collectMembersAt(root, [], false, state);
  const members = [...state.members.values()];
  return {
    status: t.isObjectExpression(node) ? "object-literal" : "object-binding",
    members: [
      ...new Set(
        members
          .filter((member) => !member.conditional)
          .map((member) => member.segments.join(".")),
      ),
    ].sort(compareUnicodeCodePoints),
    conditional_members: [
      ...new Set(
        members
          .filter((member) => member.conditional)
          .map((member) => member.segments.join(".")),
      ),
    ].sort(compareUnicodeCodePoints),
    unknown: state.unknown,
  };
};

interface MemberState {
  readonly members: Map<
    string,
    { readonly segments: readonly string[]; readonly conditional: boolean }
  >;
  readonly expanded: Set<t.ObjectExpression>;
  unknown: number;
  readonly objects: ReadonlyMap<number, ElectronApiObject>;
}

const boundObject = (
  node: t.Node,
  state: MemberState,
): t.ObjectExpression | undefined => {
  const expression = unwrapJavaScriptExpression(node).node;
  if (t.isObjectExpression(expression)) return expression;
  const bound = state.objects.get(expression.start ?? -1);
  if (bound === undefined || !t.isIdentifier(expression)) return undefined;
  if (bound.memberWrites) state.unknown += 1;
  return bound.object;
};

const collectMembersAt = (
  object: t.ObjectExpression,
  prefix: readonly string[],
  conditional: boolean,
  state: MemberState,
): void => {
  // Expand each source-owned object once per exposure. Cycles and repeated
  // spreads stay explicitly unknown instead of amplifying a shared initializer.
  if (prefix.length >= 8 || state.expanded.has(object)) {
    state.unknown += 1;
    for (const [key, member] of state.members)
      if (
        member.segments.length > prefix.length + 1 &&
        prefix.every((segment, index) => member.segments[index] === segment)
      )
        state.members.delete(key);
    return;
  }
  state.expanded.add(object);
  for (const property of object.properties) {
    if (t.isSpreadElement(property)) {
      collectSpread(property.argument, prefix, conditional, state);
      continue;
    }
    const name = semanticStaticPropertyKey(property.key, property.computed);
    if (name === null) {
      state.unknown += 1;
      continue;
    }
    const segments = [...prefix, name];
    for (const [key, member] of state.members)
      if (
        segments.every((segment, index) => member.segments[index] === segment)
      )
        state.members.delete(key);
    state.members.set(compositeKey(segments), { segments, conditional });
    const nested = t.isObjectProperty(property)
      ? boundObject(property.value, state)
      : undefined;
    if (nested !== undefined)
      collectMembersAt(nested, segments, conditional, state);
  }
};

// A spread contributes exact keys only when every branch is a known object.
const collectSpread = (
  argument: t.Node,
  prefix: readonly string[],
  conditional: boolean,
  state: MemberState,
): void => {
  const expression = unwrapJavaScriptExpression(argument).node;
  const branches = t.isConditionalExpression(expression)
    ? [expression.consequent, expression.alternate]
    : t.isLogicalExpression(expression)
      ? [expression.left, expression.right]
      : [expression];
  const objects = branches.map((branch) => boundObject(branch, state));
  if (objects.some((object) => object === undefined)) {
    state.unknown += 1;
    // An unknown replacement can change nested shapes, while existing own
    // top-level keys remain present after an object spread.
    for (const [key, member] of state.members)
      if (
        member.segments.length > prefix.length + 1 &&
        prefix.every((segment, index) => member.segments[index] === segment)
      )
        state.members.delete(key);
    return;
  }
  if (branches.length === 1) {
    const object = objects[0];
    if (object !== undefined)
      collectMembersAt(object, prefix, conditional, state);
    return;
  }
  const alternatives: MemberState[] = [];
  for (const object of objects) {
    if (object === undefined) continue;
    const branch: MemberState = {
      ...state,
      members: new Map(state.members),
      unknown: 0,
    };
    collectMembersAt(object, prefix, conditional, branch);
    alternatives.push(branch);
    state.unknown += branch.unknown;
  }
  state.members.clear();
  for (const branch of alternatives)
    for (const [key, member] of branch.members)
      state.members.set(key, {
        segments: member.segments,
        conditional:
          member.conditional ||
          alternatives.some(
            (alternative) =>
              !alternative.members.has(key) ||
              alternative.members.get(key)?.conditional === true,
          ),
      });
};
