import * as t from "@babel/types";

import { readExactJavaScriptLiteral } from "./javascriptAstValues.js";
import type {
  JavaScriptSemanticPrimitive,
  JavaScriptSemanticValue,
} from "./javascriptSemanticValueTypes.js";

/**
 * The exact value of one expression in a static finding. `literal` values are
 * spelled by syntax; `derived` values were folded from constant operators or
 * resolved through once-bound identifiers.
 */
export type JavaScriptStaticConstant =
  | {
      readonly status: "literal" | "derived";
      readonly value: JavaScriptSemanticPrimitive;
    }
  | { readonly status: "dynamic" };

/** Read static finding values through one semantic value evaluator. */
export type JavaScriptStaticConstantReader = (
  node: t.Node | null | undefined,
) => JavaScriptStaticConstant;

/**
 * Combine literal syntax with exact semantic evaluation for static findings.
 * Without an evaluator, only literal syntax has a value.
 */
export const createJavaScriptStaticConstantReader =
  (
    evaluate: ((node: t.Node) => JavaScriptSemanticValue) | undefined,
  ): JavaScriptStaticConstantReader =>
  (node) => {
    if (node === null || node === undefined) return { status: "dynamic" };
    const literal = literalValue(node);
    if (literal !== undefined)
      return { status: "literal", value: literal.value };
    if (evaluate === undefined || !t.isExpression(node))
      return { status: "dynamic" };
    const value = evaluate(node);
    return value.status === "literal"
      ? { status: "derived", value: value.value }
      : { status: "dynamic" };
  };

/** Read a string value from a static constant. */
export const staticConstantString = (
  constant: JavaScriptStaticConstant,
): string | undefined =>
  constant.status !== "dynamic" && typeof constant.value === "string"
    ? constant.value
    : undefined;

const literalValue = (
  node: t.Node,
): { readonly value: JavaScriptSemanticPrimitive } | undefined => {
  const literal = readExactJavaScriptLiteral(node);
  if (literal.found) return literal;
  // A negated numeric literal is how syntax spells a negative number.
  if (
    t.isUnaryExpression(node, { operator: "-" }) &&
    t.isNumericLiteral(node.argument)
  ) {
    const value = -node.argument.value;
    return Number.isFinite(value) && !Object.is(value, -0)
      ? { value }
      : undefined;
  }
  return undefined;
};
