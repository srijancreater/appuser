import * as t from "@babel/types";

import {
  semanticStaticPropertyKey,
  unwrapJavaScriptExpression,
} from "./javascriptAstValues.js";
import type {
  JavaScriptSemanticPrimitive,
  JavaScriptSemanticValue,
} from "./javascriptSemanticValueTypes.js";
import { semanticPrimitiveSet } from "./javascriptSemanticPrimitives.js";
import {
  SEMANTIC_EXPRESSION_DEPTH_LIMIT,
  SEMANTIC_PRIMITIVE_CANDIDATE_LIMIT,
  exceedsSemanticPrimitiveAdditionByteBudget,
  exceedsSemanticTemplateByteBudget,
  semanticResourceLimitUnknown,
} from "./javascriptSemanticResourceLimits.js";
import {
  isUnshadowedGlobal,
  type JavaScriptSemanticAnalysisState,
} from "./javascriptSemanticState.js";

/**
 * One exact primitive operand. Operands may hold `undefined`, `NaN`, the
 * infinities, and negative zero while an expression is folded; only the final
 * value must fit the JSON primitive lattice.
 */
export type JavaScriptSemanticOperand = JavaScriptSemanticPrimitive | undefined;

/**
 * A leaf proven to be an object whose identity and primitive coercion are
 * unknown. Only strict equality with a primitive and loose equality with a
 * nullish value compare it exactly; every other operator yields unknown.
 */
export const SEMANTIC_OBJECT_OPERAND: unique symbol = Symbol("object operand");

/** One exact candidate of a leaf expression the folder reads. */
export type SemanticLeafOperand =
  | JavaScriptSemanticOperand
  | typeof SEMANTIC_OBJECT_OPERAND;

// Operands are primitives, so the casts select JavaScript's own coercions and
// the host operators compute exact results without invoking application code.
type BinaryOperator = (
  left: number,
  right: number,
) => JavaScriptSemanticOperand;

const BINARY_OPERATORS: ReadonlyMap<string, BinaryOperator> = new Map<
  string,
  BinaryOperator
>([
  ["+", (left, right) => left + right],
  ["-", (left, right) => left - right],
  ["*", (left, right) => left * right],
  ["/", (left, right) => left / right],
  ["%", (left, right) => left % right],
  ["**", (left, right) => left ** right],
  ["==", (left, right) => left == right],
  ["!=", (left, right) => left != right],
  ["===", (left, right) => left === right],
  ["!==", (left, right) => left !== right],
  ["<", (left, right) => left < right],
  ["<=", (left, right) => left <= right],
  [">", (left, right) => left > right],
  [">=", (left, right) => left >= right],
  ["<<", (left, right) => left << right],
  [">>", (left, right) => left >> right],
  [">>>", (left, right) => left >>> right],
  ["&", (left, right) => left & right],
  ["|", (left, right) => left | right],
  ["^", (left, right) => left ^ right],
]);

/** Binary operators whose primitive operands cannot invoke application code. */
const isFoldableSemanticBinaryOperator = (operator: string): boolean =>
  BINARY_OPERATORS.has(operator);

/** Apply one foldable binary operator to primitive operands. */
const applySemanticBinaryOperator = (
  operator: string,
  left: JavaScriptSemanticOperand,
  right: JavaScriptSemanticOperand,
): JavaScriptSemanticOperand => {
  const apply = BINARY_OPERATORS.get(operator);
  if (apply === undefined)
    throw new TypeError(`Unsupported folded operator ${operator}`);
  return apply(left as number, right as number);
};

/** Exact equality between an object and another operand, if it has one. */
const compareObject = (
  operator: string,
  other: SemanticLeafOperand,
): boolean | undefined => {
  const strict = operator === "===" || operator === "!==";
  if (!strict && operator !== "==" && operator !== "!=") return undefined;
  // Two objects compare by identity; loose equality coerces the object
  // unless the other operand is nullish.
  if (
    other === SEMANTIC_OBJECT_OPERAND ||
    (!strict && other !== null && other !== undefined)
  )
    return undefined;
  return operator.startsWith("!");
};

/** Apply one side-effect-free unary operator, or report it as unsupported. */
const applySemanticUnaryOperator = (
  operator: string,
  argument: SemanticLeafOperand,
): { readonly value: JavaScriptSemanticOperand } | undefined => {
  if (argument === SEMANTIC_OBJECT_OPERAND)
    return operator === "!" ? { value: false } : undefined;
  switch (operator) {
    case "!":
      return { value: !argument };
    case "-":
      return { value: -(argument as number) };
    case "+":
      return { value: +(argument as number) };
    case "~":
      return { value: ~(argument as number) };
    case "typeof":
      return { value: typeof argument };
    default:
      return undefined;
  }
};

/** Convert folded operands to a JSON lattice value without losing exactness. */
export const semanticOperandValue = (
  operands: readonly JavaScriptSemanticOperand[],
): JavaScriptSemanticValue =>
  operands.includes(undefined)
    ? {
        status: "unknown",
        reason: "undefined is outside the JSON primitive lattice.",
      }
    : semanticPrimitiveSet(operands as readonly JavaScriptSemanticPrimitive[]);

/** The text `Array.prototype.join` produces for one primitive element. */
const semanticJoinText = (value: JavaScriptSemanticOperand): string =>
  value === null || value === undefined ? "" : String(value);

/** Why an expression has no exact primitive operand candidates. */
export type SemanticOperandFailure = Extract<
  JavaScriptSemanticValue,
  { readonly status: "unknown" | "ambiguous" | "cycle" }
>;

/** Exact primitive candidates of one expression, or why they are unknown. */
export type SemanticOperands =
  | readonly JavaScriptSemanticOperand[]
  | SemanticOperandFailure;

/** Exact candidates of one leaf expression, or why they are unknown. */
export type SemanticLeafOperands =
  | readonly SemanticLeafOperand[]
  | SemanticOperandFailure;

export const isSemanticOperands = <Operand>(
  result: readonly Operand[] | SemanticOperandFailure,
): result is readonly Operand[] => Array.isArray(result);

/** Keep primitive candidates; an object candidate cannot become text or a number. */
const primitiveOperands = (
  values: readonly SemanticLeafOperand[],
  reason: string,
): SemanticOperands =>
  values.includes(SEMANTIC_OBJECT_OPERAND)
    ? { status: "unknown", reason }
    : (values as readonly JavaScriptSemanticOperand[]);

/** Keep a lattice failure, or explain why a non-primitive cannot be an operand. */
export const semanticOperandFailure = (
  value: JavaScriptSemanticValue,
  reason: string,
): SemanticOperandFailure =>
  value.status === "unknown" ||
  value.status === "ambiguous" ||
  value.status === "cycle"
    ? value
    : { status: "unknown", reason };

/**
 * Values of the expressions the operator folder does not own. The constant
 * lattice reads them from once-bound bindings; symbolic substitution reads
 * them from its call-site environments.
 */
export interface SemanticOperandLeaves {
  readonly state: JavaScriptSemanticAnalysisState;
  /** Exact candidates of a non-operator expression. */
  readonly operands: (node: t.Node, depth: number) => SemanticLeafOperands;
  /**
   * Element candidates of a `join` receiver that is not array syntax; a hole
   * or absent element is `[undefined]`.
   */
  readonly arrayItems: (
    node: t.Node,
    depth: number,
  ) => readonly (readonly SemanticLeafOperand[])[] | SemanticOperandFailure;
}

/** Operator syntax the folder evaluates itself rather than as a leaf. */
export const isSemanticOperatorExpression = (node: t.Node): boolean => {
  if (t.isBinaryExpression(node))
    return isFoldableSemanticBinaryOperator(node.operator);
  if (t.isUnaryExpression(node) || t.isTemplateLiteral(node)) return true;
  if (!t.isCallExpression(node)) return false;
  const callee = unwrapJavaScriptExpression(node.callee).node;
  if (
    !t.isMemberExpression(callee) ||
    node.arguments.some((argument) => !t.isExpression(argument))
  )
    return false;
  const method = semanticStaticPropertyKey(callee.property, callee.computed);
  return (
    method === "fromCharCode" ||
    (method === "join" && node.arguments.length <= 1)
  );
};

/**
 * Fold primitive operators, templates, `String.fromCharCode` and
 * `Array.prototype.join` over exact candidates, including values JSON
 * evidence cannot carry. Every other expression is a leaf.
 */
export const foldSemanticOperands = (
  node: t.Node,
  leaves: SemanticOperandLeaves,
  depth: number,
): SemanticOperands => {
  const folded = foldOperand(node, leaves, depth);
  return isSemanticOperands(folded)
    ? primitiveOperands(folded, "Expression is an object.")
    : folded;
};

const foldOperand = (
  node: t.Node,
  leaves: SemanticOperandLeaves,
  depth: number,
): SemanticLeafOperands => {
  if (depth > SEMANTIC_EXPRESSION_DEPTH_LIMIT)
    return semanticResourceLimitUnknown("expression-depth");
  const unwrapped = unwrapJavaScriptExpression(node);
  if (unwrapped.depth > 0) {
    if (depth + unwrapped.depth > SEMANTIC_EXPRESSION_DEPTH_LIMIT)
      return semanticResourceLimitUnknown("expression-depth");
    return foldOperand(unwrapped.node, leaves, depth + unwrapped.depth);
  }
  if (isSemanticOperatorExpression(node)) {
    if (t.isBinaryExpression(node)) return foldBinary(node, leaves, depth);
    if (t.isUnaryExpression(node)) return foldUnary(node, leaves, depth);
    if (t.isTemplateLiteral(node)) return foldTemplate(node, leaves, depth);
    if (t.isCallExpression(node)) return foldCall(node, leaves, depth);
  }
  if (t.isIdentifier(node) && GLOBAL_CONSTANTS.has(node.name)) {
    if (isUnshadowedGlobal(node, leaves.state, node.name))
      return [globalConstant(node.name)];
  }
  return leaves.operands(node, depth);
};

const GLOBAL_CONSTANTS = new Set(["undefined", "NaN", "Infinity"]);

const globalConstant = (name: string): JavaScriptSemanticOperand =>
  name === "NaN" ? Number.NaN : name === "Infinity" ? Infinity : undefined;

const foldBinary = (
  node: t.BinaryExpression,
  leaves: SemanticOperandLeaves,
  depth: number,
): SemanticLeafOperands => {
  // Minified concatenations nest thousands deep on the left; walk iteratively.
  const pending: {
    readonly node: t.BinaryExpression;
    left: readonly SemanticLeafOperand[] | undefined;
  }[] = [];
  let current: t.Node = node;
  for (;;) {
    if (
      t.isBinaryExpression(current) &&
      isFoldableSemanticBinaryOperator(current.operator)
    ) {
      pending.push({ node: current, left: undefined });
      current = current.left;
      continue;
    }
    let result = foldOperand(current, leaves, depth + 1);
    for (;;) {
      if (!isSemanticOperands(result)) return result;
      const parent = pending.at(-1);
      if (parent === undefined) return result;
      if (parent.left === undefined) {
        parent.left = result;
        current = parent.node.right;
        break;
      }
      result = combineOperands(parent.node.operator, parent.left, result);
      pending.pop();
    }
  }
};

const combineOperands = (
  operator: string,
  left: readonly SemanticLeafOperand[],
  right: readonly SemanticLeafOperand[],
): SemanticOperands => {
  if (left.length > SEMANTIC_PRIMITIVE_CANDIDATE_LIMIT / right.length)
    return semanticResourceLimitUnknown("primitive-candidates");
  const leftPrimitives = primitiveOperands(left, "");
  const rightPrimitives = primitiveOperands(right, "");
  if (isSemanticOperands(leftPrimitives) && isSemanticOperands(rightPrimitives))
    return operator === "+" &&
      exceedsSemanticPrimitiveAdditionByteBudget(
        leftPrimitives,
        rightPrimitives,
      )
      ? semanticResourceLimitUnknown("primitive-bytes")
      : uniqueOperands(
          leftPrimitives.flatMap((leftValue) =>
            rightPrimitives.map((rightValue) =>
              applySemanticBinaryOperator(operator, leftValue, rightValue),
            ),
          ),
        );
  const values: JavaScriptSemanticOperand[] = [];
  for (const leftValue of left)
    for (const rightValue of right) {
      if (
        leftValue !== SEMANTIC_OBJECT_OPERAND &&
        rightValue !== SEMANTIC_OBJECT_OPERAND
      ) {
        values.push(
          applySemanticBinaryOperator(operator, leftValue, rightValue),
        );
        continue;
      }
      const compared = compareObject(
        operator,
        leftValue === SEMANTIC_OBJECT_OPERAND ? rightValue : leftValue,
      );
      if (compared === undefined)
        return {
          status: "unknown",
          reason: `Operator ${operator} reads an object operand.`,
        };
      values.push(compared);
    }
  return uniqueOperands(values);
};

const foldUnary = (
  node: t.UnaryExpression,
  leaves: SemanticOperandLeaves,
  depth: number,
): SemanticLeafOperands => {
  // `void` discards its argument's value whatever that value is.
  if (node.operator === "void") return [undefined];
  const argument = foldOperand(node.argument, leaves, depth + 1);
  if (!isSemanticOperands(argument)) return argument;
  const values: JavaScriptSemanticOperand[] = [];
  for (const value of argument) {
    const applied = applySemanticUnaryOperator(node.operator, value);
    if (applied === undefined)
      return {
        status: "unknown",
        reason: `Unsupported unary ${node.operator}.`,
      };
    values.push(applied.value);
  }
  return uniqueOperands(values);
};

const foldCall = (
  node: t.CallExpression,
  leaves: SemanticOperandLeaves,
  depth: number,
): SemanticOperands => {
  const callee = unwrapJavaScriptExpression(node.callee)
    .node as t.MemberExpression;
  const method = semanticStaticPropertyKey(callee.property, callee.computed);
  const receiver = unwrapJavaScriptExpression(callee.object).node;
  if (method === "join")
    return foldJoin(receiver, node.arguments[0], leaves, depth);
  return isUnshadowedGlobal(receiver, leaves.state, "String")
    ? foldCharacterCodes(node.arguments, leaves, depth)
    : { status: "unknown", reason: "Unsupported CallExpression value." };
};

const foldCharacterCodes = (
  codes: t.CallExpression["arguments"],
  leaves: SemanticOperandLeaves,
  depth: number,
): SemanticOperands => {
  let candidates = [""];
  for (const code of codes) {
    const values = foldSemanticOperands(code, leaves, depth + 1);
    if (!isSemanticOperands(values)) return values;
    if (candidates.length > SEMANTIC_PRIMITIVE_CANDIDATE_LIMIT / values.length)
      return semanticResourceLimitUnknown("primitive-candidates");
    const suffixes = values.map((value) => String.fromCharCode(Number(value)));
    candidates = candidates.flatMap((prefix) =>
      suffixes.map((suffix) => `${prefix}${suffix}`),
    );
  }
  return uniqueOperands(candidates);
};

/** Element texts of an exact array; literal elements may be `undefined`. */
const joinItems = (
  receiver: t.Node,
  leaves: SemanticOperandLeaves,
  depth: number,
): (readonly string[])[] | SemanticOperandFailure => {
  if (!t.isArrayExpression(receiver)) {
    const items = leaves.arrayItems(receiver, depth + 1);
    if (!Array.isArray(items)) return items as SemanticOperandFailure;
    const texts: (readonly string[])[] = [];
    for (const item of items) {
      const values = primitiveOperands(item, "Join item is an object.");
      if (!isSemanticOperands(values)) return values;
      texts.push(values.map(semanticJoinText));
    }
    return texts;
  }
  const items: (readonly string[])[] = [];
  for (const element of receiver.elements) {
    if (element === null) {
      items.push([""]);
      continue;
    }
    if (t.isSpreadElement(element))
      return { status: "unknown", reason: "Join receiver has a spread." };
    const values = foldSemanticOperands(element, leaves, depth + 1);
    if (!isSemanticOperands(values)) return values;
    items.push(values.map(semanticJoinText));
  }
  return items;
};

const foldJoin = (
  receiver: t.Node,
  separatorNode: t.CallExpression["arguments"][number] | undefined,
  leaves: SemanticOperandLeaves,
  depth: number,
): SemanticOperands => {
  const items = joinItems(receiver, leaves, depth);
  if (!Array.isArray(items)) return items;
  const separators =
    separatorNode === undefined
      ? [","]
      : foldSemanticOperands(separatorNode, leaves, depth + 1);
  if (!isSemanticOperands(separators)) return separators;
  const joined: string[] = [];
  for (const separator of separators) {
    const text = separator === undefined ? "," : String(separator);
    let candidates = [""];
    for (const [index, values] of items.entries()) {
      const suffixes =
        index === 0 ? values : values.map((value) => `${text}${value}`);
      if (
        candidates.length * joined.length >
          SEMANTIC_PRIMITIVE_CANDIDATE_LIMIT ||
        candidates.length > SEMANTIC_PRIMITIVE_CANDIDATE_LIMIT / suffixes.length
      )
        return semanticResourceLimitUnknown("primitive-candidates");
      if (exceedsSemanticTemplateByteBudget(candidates, suffixes))
        return semanticResourceLimitUnknown("primitive-bytes");
      candidates = candidates.flatMap((prefix) =>
        suffixes.map((suffix) => `${prefix}${suffix}`),
      );
    }
    joined.push(...candidates);
  }
  return uniqueOperands(joined);
};

const foldTemplate = (
  node: t.TemplateLiteral,
  leaves: SemanticOperandLeaves,
  depth: number,
): SemanticOperands => {
  let candidates = [""];
  for (let index = 0; index < node.quasis.length; index += 1) {
    const quasi = node.quasis[index];
    const text = quasi?.value.cooked;
    if (text === undefined || text === null)
      return {
        status: "unknown",
        reason: "Template text has no cooked representation.",
      };
    if (exceedsSemanticTemplateByteBudget(candidates, [text]))
      return semanticResourceLimitUnknown("primitive-bytes");
    candidates = candidates.map((prefix) => `${prefix}${text}`);
    const expression = node.expressions[index];
    if (expression === undefined) continue;
    const values = foldSemanticOperands(expression, leaves, depth + 1);
    if (!isSemanticOperands(values)) {
      if (values.status === "unknown" && values.resourceLimit !== undefined)
        return values;
      return {
        status: "unknown",
        reason: "Template expression is not a bounded primitive.",
      };
    }
    if (candidates.length > SEMANTIC_PRIMITIVE_CANDIDATE_LIMIT / values.length)
      return semanticResourceLimitUnknown("primitive-candidates");
    const suffixes = values.map((value) => String(value));
    if (exceedsSemanticTemplateByteBudget(candidates, suffixes))
      return semanticResourceLimitUnknown("primitive-bytes");
    candidates = candidates.flatMap((prefix) =>
      suffixes.map((suffix) => `${prefix}${suffix}`),
    );
  }
  return uniqueOperands(candidates);
};

const uniqueOperands = (
  values: readonly JavaScriptSemanticOperand[],
): readonly JavaScriptSemanticOperand[] => {
  const unique: JavaScriptSemanticOperand[] = [];
  for (const value of values)
    if (!unique.some((existing) => Object.is(existing, value)))
      unique.push(value);
  return unique;
};
