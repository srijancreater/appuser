import * as t from "@babel/types";

import { semanticStaticPropertyKey } from "./javascriptAstValues.js";
import { addLocatedFinding } from "./javascriptStaticAnalysisFindings.js";
import {
  calleeName,
  range,
  sourceSlice,
} from "./javascriptStaticAnalysisHelpers.js";
import type { JavaScriptFindingContext } from "./javascriptStaticAnalysisState.js";
import { staticConstantString } from "./javascriptStaticConstants.js";
import { classifyJavaScriptUrlValue } from "./javascriptUrlValues.js";
import { sanitizeEndpointCandidate } from "../browserObservation.js";
import { compositeKey } from "../unicodeCodePointOrder.js";

/**
 * Record URL, host, and path values present in string data: literals,
 * template text, and exact values folded from constant expressions. Values
 * already reported at a recognized call site or route are not repeated.
 */
export const inspectDataEndpointNode = (
  node: t.Node,
  parent: t.Node | null,
  readAncestors: () => readonly t.Node[],
  context: JavaScriptFindingContext,
): void => {
  const consumed = context.accumulator.consumedValueNodes;
  if (consumed.has(node)) return;
  if (t.isStringLiteral(node)) {
    if (isModuleSpecifier(parent)) return;
    addDataEndpoint(context, {
      node,
      value: node.value,
      expression: null,
      mechanism:
        t.isObjectProperty(parent) && parent.key === node
          ? "property-key"
          : "string-literal",
      readAncestors,
    });
    return;
  }
  if (isFoldableData(node, parent)) {
    const value = staticConstantString(context.constants(node));
    if (
      value !== undefined &&
      addDataEndpoint(context, {
        node,
        value,
        expression: sourceSlice(context.source, node),
        mechanism: "folded-expression",
        readAncestors,
      })
    ) {
      consumeValueNodes(context, node);
      return;
    }
  }
  if (t.isTemplateLiteral(node))
    for (const quasi of node.quasis) {
      const text = quasi.value.cooked;
      if (text !== null && text !== undefined)
        addDataEndpoint(context, {
          node: quasi,
          value: text,
          expression: null,
          mechanism: "template-text",
          readAncestors: () => [...readAncestors(), node],
        });
    }
};

/** Exclude a reported value expression and its literals from data findings. */
export const consumeValueNodes = (
  context: JavaScriptFindingContext,
  root: t.Node,
): void => {
  const pending = [root];
  const consumed = context.accumulator.consumedValueNodes;
  while (pending.length > 0) {
    const node = pending.pop();
    if (node === undefined) break;
    consumed.add(node);
    if (t.isBinaryExpression(node)) pending.push(node.left, node.right);
    else if (t.isTemplateLiteral(node)) pending.push(...node.expressions);
    else if (t.isCallExpression(node))
      pending.push(node.callee, ...node.arguments);
    else if (t.isMemberExpression(node)) pending.push(node.object);
    else if (t.isArrayExpression(node))
      for (const element of node.elements)
        if (element !== null) pending.push(element);
  }
};

interface DataEndpointInput {
  readonly node: t.Node;
  readonly value: string;
  readonly expression: string | null;
  readonly mechanism: string;
  readonly readAncestors: () => readonly t.Node[];
}

const addDataEndpoint = (
  context: JavaScriptFindingContext,
  input: DataEndpointInput,
): boolean => {
  if (classifyJavaScriptUrlValue(input.value) === undefined) return false;
  addLocatedFinding(context, {
    collection: context.accumulator.endpoints,
    key: compositeKey(["endpoint", "data", input.value]),
    node: input.node,
    value: {
      kind: "data",
      value: sanitizeEndpointCandidate(input.value),
      expression: input.expression,
      mechanism: input.mechanism,
      property_path: containingPath(input.node, input.readAncestors()),
      module_key: null,
      location: range(input.node),
    },
  });
  return true;
};

// Only maximal expressions are folded; their operands are covered by the result.
const isFoldableData = (node: t.Node, parent: t.Node | null): boolean => {
  if (t.isTemplateLiteral(node))
    return !t.isTaggedTemplateExpression(parent) && node.expressions.length > 0;
  if (t.isBinaryExpression(node, { operator: "+" }))
    return !t.isBinaryExpression(parent, { operator: "+" });
  if (!t.isCallExpression(node)) return false;
  const name = calleeName(node.callee);
  return name === "String.fromCharCode" || name.endsWith(".join");
};

const isModuleSpecifier = (parent: t.Node | null): boolean =>
  t.isImportDeclaration(parent) ||
  t.isExportAllDeclaration(parent) ||
  t.isExportNamedDeclaration(parent) ||
  t.isImportExpression(parent) ||
  (t.isCallExpression(parent) && calleeName(parent.callee) === "require");

/**
 * Static keys from the nearest named container to a value, such as
 * `["Voice", "DIALABLE_ORIGIN"]` or `["PROVIDERS", "Map()", "0", "0", "0"]`,
 * where `Map()` marks a call argument. Returns null when the value has no
 * object, array, class, call, or binding container.
 */
const containingPath = (
  node: t.Node,
  ancestors: readonly t.Node[],
): readonly string[] | null => {
  const path: string[] = [];
  let child = node;
  for (const parent of ancestors.toReversed()) {
    const step = containerStep(parent, child);
    if (step === undefined) break;
    path.unshift(...step.segments);
    if (step.root) break;
    child = parent;
  }
  return path.length === 0 ? null : path;
};

interface ContainerStep {
  readonly segments: readonly string[];
  /** The step names the container root, such as a binding or class. */
  readonly root: boolean;
}

const TRANSPARENT_CONTAINERS = new Set([
  "ObjectExpression",
  "ConditionalExpression",
  "LogicalExpression",
  "SequenceExpression",
  "ParenthesizedExpression",
  "TemplateLiteral",
  "ClassBody",
]);

const containerStep = (
  parent: t.Node,
  child: t.Node,
): ContainerStep | undefined => {
  if (TRANSPARENT_CONTAINERS.has(parent.type))
    return { segments: [], root: false };
  if (t.isObjectProperty(parent) || t.isClassProperty(parent))
    return {
      segments:
        parent.value === child
          ? [
              semanticStaticPropertyKey(parent.key, parent.computed) ??
                "[computed]",
            ]
          : [],
      root: false,
    };
  if (t.isClassPrivateProperty(parent))
    return { segments: [`#${parent.key.id.name}`], root: false };
  if (t.isArrayExpression(parent))
    return {
      segments: [String(parent.elements.indexOf(child as t.Expression))],
      root: false,
    };
  if (
    (t.isCallExpression(parent) || t.isNewExpression(parent)) &&
    parent.callee !== child
  ) {
    const name = calleeName(parent.callee);
    return {
      segments: [
        `${name === "" ? "[call]" : name}()`,
        String(parent.arguments.indexOf(child as t.Expression)),
      ],
      root: false,
    };
  }
  return rootStep(parent);
};

const rootStep = (parent: t.Node): ContainerStep | undefined => {
  if (t.isVariableDeclarator(parent))
    return {
      segments: t.isIdentifier(parent.id) ? [parent.id.name] : [],
      root: true,
    };
  if (t.isAssignmentExpression(parent)) {
    const target = calleeName(parent.left);
    return { segments: target === "" ? [] : [target], root: true };
  }
  if (t.isClass(parent))
    return parent.id === null || parent.id === undefined
      ? { segments: [], root: false }
      : { segments: [parent.id.name], root: true };
  return undefined;
};
