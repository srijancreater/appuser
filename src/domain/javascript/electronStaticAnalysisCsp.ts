import { htmlArtifactReferences } from "./htmlArtifactReferences.js";
import * as t from "@babel/types";

import {
  DYNAMIC_SOURCE,
  parseContentSecurityPolicy,
} from "./contentSecurityPolicy.js";
import type { ElectronContentSecurityPolicyFinding } from "./electronStaticAnalysisTypes.js";
import { boundedExpression } from "./electronStaticAnalysisValues.js";
import { compositeKey } from "../unicodeCodePointOrder.js";
import { semanticStaticPropertyKey } from "./javascriptAstValues.js";
import { addLocatedFinding } from "./javascriptStaticAnalysisFindings.js";
import { argumentNode, range } from "./javascriptStaticAnalysisHelpers.js";
import type { JavaScriptFindingContext } from "./javascriptStaticAnalysisState.js";
import {
  staticConstantString,
  type JavaScriptStaticConstantReader,
} from "./javascriptStaticConstants.js";

const HEADER = /^content-security-policy(?:-report-only)?$/iu;
// Cheap prefilter before splitting arbitrary literals into directives.
const CANDIDATE = /(?:-src|base-uri|form-action|frame-ancestors)\b/u;

interface PolicyText {
  readonly text: string;
  readonly dynamicParts: number;
}

/**
 * Recover Content-Security-Policy text from header properties and
 * assignments, `[...].join(sep)` directive lists, and string or template
 * literals, including `<meta http-equiv>` markup inside them. Runtime parts of
 * templates and joins are kept as a placeholder and are not judged.
 */
export const inspectContentSecurityPolicyNode = (
  node: t.Node,
  context: JavaScriptFindingContext,
): void => {
  const consumed = context.accumulator.policyNodes;
  const { constants } = context;
  if (consumed.has(node)) return;
  if (t.isObjectProperty(node) || t.isAssignmentExpression(node)) {
    const header = headerName(node);
    if (header === undefined) return;
    const value = t.isObjectProperty(node) ? node.value : node.right;
    markConsumed(value, consumed);
    const policy = policyText(value, constants);
    addPolicy(context, node, {
      mechanism: "header-property",
      header: header.toLowerCase(),
      policy,
      expression:
        policy === undefined ? boundedExpression(context.source, value) : null,
      requireMultiple: false,
    });
    return;
  }
  if (isDirectiveJoin(node)) {
    const policy = policyText(node, constants);
    if (policy === undefined || !CANDIDATE.test(policy.text)) return;
    markConsumed(node, consumed);
    addPolicy(context, node, {
      mechanism: "directive-list",
      header: null,
      policy,
      expression: null,
      requireMultiple: true,
    });
    return;
  }
  if (t.isStringLiteral(node) || t.isTemplateLiteral(node))
    inspectPolicyLiteral(node, context);
};

const inspectPolicyLiteral = (
  node: t.StringLiteral | t.TemplateLiteral,
  context: JavaScriptFindingContext,
): void => {
  const spelled = t.isStringLiteral(node)
    ? node.value
    : node.quasis.map(({ value }) => value.raw).join(" ");
  if (!CANDIDATE.test(spelled)) return;
  const policy = policyText(node, context.constants);
  if (policy === undefined || !CANDIDATE.test(policy.text)) return;
  const metas = htmlArtifactReferences(policy.text).policies;
  if (metas.length === 0) {
    addPolicy(context, node, {
      mechanism: "string-literal",
      header: null,
      policy,
      expression: null,
      requireMultiple: true,
    });
    return;
  }
  for (const meta of metas) {
    const text = meta.content;
    addPolicy(context, node, {
      mechanism: "html-meta-string",
      header: meta.header,
      policy: { text, dynamicParts: text.split(DYNAMIC_SOURCE).length - 1 },
      expression: null,
      requireMultiple: false,
    });
  }
};

const addPolicy = (
  context: JavaScriptFindingContext,
  node: t.Node,
  input: {
    readonly mechanism: ElectronContentSecurityPolicyFinding["mechanism"];
    readonly header: string | null;
    readonly policy: PolicyText | undefined;
    readonly expression: string | null;
    readonly requireMultiple: boolean;
  },
): void => {
  const parsed =
    input.policy === undefined
      ? undefined
      : parseContentSecurityPolicy(input.policy.text, input.requireMultiple);
  // Literals and lists that do not parse are ordinary text, not policies.
  if (parsed === undefined && input.mechanism !== "header-property") return;
  if (input.policy === undefined || input.policy.dynamicParts > 0)
    context.accumulator.unknownFindings += 1;
  const finding: ElectronContentSecurityPolicyFinding = {
    mechanism: input.mechanism,
    header: input.header,
    policy: input.policy?.text ?? null,
    policy_expression: input.expression,
    directives: parsed?.directives ?? [],
    concerns: parsed?.concerns ?? [],
    dynamic_parts: input.policy?.dynamicParts ?? 1,
    module_key: null,
    location: range(node),
  };
  addLocatedFinding(context, {
    collection: context.accumulator.contentSecurityPolicies,
    key: compositeKey([
      "content-security-policy",
      input.mechanism,
      finding.policy ?? finding.policy_expression ?? "",
    ]),
    node,
    value: finding,
  });
};

const headerName = (
  node: t.ObjectProperty | t.AssignmentExpression,
): string | undefined => {
  const key = t.isObjectProperty(node)
    ? semanticStaticPropertyKey(node.key, node.computed)
    : t.isMemberExpression(node.left)
      ? semanticStaticPropertyKey(node.left.property, node.left.computed)
      : null;
  return key !== null && HEADER.test(key) ? key : undefined;
};

const isDirectiveJoin = (node: t.Node): node is t.CallExpression =>
  t.isCallExpression(node) &&
  t.isMemberExpression(node.callee) &&
  t.isArrayExpression(node.callee.object) &&
  semanticStaticPropertyKey(node.callee.property, node.callee.computed) ===
    "join";

// Whole values come from the shared constant evaluator. Only a partly
// computed template, join, or concatenation is assembled here, keeping each
// runtime part as a placeholder that the evaluator cannot represent.
const policyText = (
  node: t.Node,
  constants: JavaScriptStaticConstantReader,
): PolicyText | undefined => {
  const constant = staticConstantString(constants(node));
  if (constant !== undefined) return { text: constant, dynamicParts: 0 };
  if (t.isTemplateLiteral(node)) {
    const cooked = node.quasis.map(({ value }) => value.cooked);
    if (cooked.some((part) => part === null || part === undefined))
      return undefined;
    return {
      text: cooked.join(DYNAMIC_SOURCE),
      dynamicParts: node.expressions.length,
    };
  }
  if (t.isArrayExpression(node) && node.elements.length === 1) {
    const [only] = node.elements;
    return only === null || only === undefined || t.isSpreadElement(only)
      ? undefined
      : policyText(only, constants);
  }
  if (isDirectiveJoin(node)) return joinedPolicyText(node, constants);
  if (t.isBinaryExpression(node, { operator: "+" })) {
    const left = policyText(node.left, constants);
    const right = policyText(node.right, constants);
    return {
      text: `${left?.text ?? DYNAMIC_SOURCE}${right?.text ?? DYNAMIC_SOURCE}`,
      dynamicParts: (left?.dynamicParts ?? 1) + (right?.dynamicParts ?? 1),
    };
  }
  return undefined;
};

const joinedPolicyText = (
  node: t.CallExpression,
  constants: JavaScriptStaticConstantReader,
): PolicyText | undefined => {
  const separator = argumentNode(node.arguments[0]);
  const joiner =
    separator === undefined ? "," : staticConstantString(constants(separator));
  if (joiner === undefined || !t.isMemberExpression(node.callee))
    return undefined;
  const array = node.callee.object;
  if (!t.isArrayExpression(array)) return undefined;
  const parts = array.elements.map((element) =>
    element === null || t.isSpreadElement(element)
      ? undefined
      : policyText(element, constants),
  );
  if (parts.some((part) => part === undefined)) return undefined;
  const known = parts.filter((part): part is PolicyText => part !== undefined);
  return {
    text: known.map(({ text }) => text).join(joiner),
    dynamicParts: known.reduce(
      (sum, { dynamicParts }) => sum + dynamicParts,
      0,
    ),
  };
};

// Literals inside a recognized policy are not reported again on their own.
const markConsumed = (node: t.Node, consumed: WeakSet<t.Node>): void => {
  const pending = [node];
  while (pending.length > 0) {
    const current = pending.pop();
    if (current === undefined) break;
    consumed.add(current);
    if (t.isArrayExpression(current)) {
      for (const element of current.elements)
        if (element !== null) pending.push(element);
    } else if (
      t.isCallExpression(current) &&
      t.isMemberExpression(current.callee)
    )
      pending.push(current.callee.object);
    else if (t.isBinaryExpression(current))
      pending.push(current.left, current.right);
  }
};
