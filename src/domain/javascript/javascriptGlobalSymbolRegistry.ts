import { parseJavaScriptSource } from "./javascriptSourceParser.js";
import * as t from "@babel/types";

import { semanticStaticPropertyKey } from "./javascriptAstValues.js";
import {
  resolveSemanticBindingState,
  semanticResolutionBlocked,
  type JavaScriptSemanticAnalysisState,
} from "./javascriptSemanticState.js";

/**
 * The key of `globalThis[Symbol.for(key)]` when both globals are unshadowed.
 * `Symbol.for` keys share one registry per realm, so sources loaded into one
 * realm reach the same slot through the same key.
 */
export const globalSymbolRegistryKey = (
  node: t.Node,
  state: JavaScriptSemanticAnalysisState,
): string | undefined => {
  const shape = registryKeyShape(node);
  return shape !== undefined &&
    unbound(shape.global, state) &&
    unbound(shape.symbol, state)
    ? shape.key
    : undefined;
};

/**
 * Values a source publishes at load: top-level `globalThis[Symbol.for(key)] =
 * value` statements. A key published more than once maps to null.
 */
export const globalSymbolRegistryPublications = (
  program: t.Program,
  state: JavaScriptSemanticAnalysisState,
): ReadonlyMap<string, t.Expression | null> => {
  const published = new Map<string, t.Expression | null>();
  for (const statement of program.body) {
    if (!t.isExpressionStatement(statement)) continue;
    const expression = statement.expression;
    if (!t.isAssignmentExpression(expression, { operator: "=" })) continue;
    const key = globalSymbolRegistryKey(expression.left, state);
    if (key === undefined) continue;
    published.set(key, published.has(key) ? null : expression.right);
  }
  return published;
};

/** One format-aware interpretation of a symbol registry expression. */
const registryKeyShape = (
  node: t.Node,
):
  | {
      readonly key: string;
      readonly global: t.Identifier;
      readonly symbol: t.Identifier;
    }
  | undefined => {
  if (
    !t.isMemberExpression(node) ||
    !node.computed ||
    !t.isIdentifier(node.object, { name: "globalThis" })
  )
    return undefined;
  const call = node.property;
  if (
    !t.isCallExpression(call) ||
    call.arguments.length !== 1 ||
    !t.isStringLiteral(call.arguments[0])
  )
    return undefined;
  const callee = call.callee;
  if (
    !t.isMemberExpression(callee) ||
    !t.isIdentifier(callee.object, { name: "Symbol" }) ||
    semanticStaticPropertyKey(callee.property, callee.computed) !== "for"
  )
    return undefined;
  return {
    key: call.arguments[0].value,
    global: node.object,
    symbol: callee.object,
  };
};

// A sole string argument is a conservative superset of supported Symbol.for
// keys, independent of identifier spelling, computed access, or shadowing.
// The zero-width scan cannot swallow a later real call inside a false candidate.
const CALL_STRING =
  /(?=\((?:\s|\/\*[\s\S]*?\*\/|\/\/[^\r\n]*(?:\r?\n|$))*("(?:[^"\\\r\n]|\\(?:\r\n|[\s\S]))*"|'(?:[^'\\\r\n]|\\(?:\r\n|[\s\S]))*')(?:\s|\/\*[\s\S]*?\*\/|\/\/[^\r\n]*(?:\r?\n|$))*(?:,(?:\s|\/\*[\s\S]*?\*\/|\/\/[^\r\n]*(?:\r?\n|$))*)?\))/gu;

/** Decode only candidate literal syntax, never parse whole files in the caller. */
export const globalSymbolRegistryCandidateKeys = (
  text: string,
): ReadonlySet<string> | undefined => {
  const keys = new Set<string>();
  // A supported registry expression needs both identifiers. Escaped identifier
  // spellings remain candidates; this filter never compares registry key text.
  const escapedIdentifier = text.includes("\\u");
  if (
    (!text.includes("Symbol") || !text.includes("globalThis")) &&
    !escapedIdentifier
  )
    return keys;
  const decoded = new Map<string, string>();
  for (const match of text.matchAll(CALL_STRING)) {
    const literal = match[1];
    if (literal === undefined) continue;
    const cached = decoded.get(literal);
    if (cached !== undefined) {
      keys.add(cached);
      continue;
    }
    const parsed = parseJavaScriptSource(`(${literal})`, "registry-literal.js");
    const statement = parsed?.program.body[0];
    if (
      !t.isExpressionStatement(statement) ||
      !t.isStringLiteral(statement.expression)
    )
      return undefined;
    decoded.set(literal, statement.expression.value);
    keys.add(statement.expression.value);
  }
  return keys;
};

/**
 * Index decoded keys once. Admit whole companion selections within one artifact's
 * input-text byte budget, bounding repeated worker copies and parsed companion
 * text to one additional input-sized pass. A refused selection stays unlinked.
 */
export const globalSymbolRegistryCompanions = <
  Source extends { readonly path: string; readonly text: string },
>(
  sources: readonly Source[],
  maximumCompanionBytes: number,
): {
  readonly companions: ReadonlyMap<string, readonly Source[]>;
  readonly limitations: readonly string[];
} => {
  const keyed: {
    readonly source: Source;
    readonly keys: ReadonlySet<string>;
    readonly bytes: number;
  }[] = [];
  const groups = new Map<
    string,
    { readonly sources: Source[]; bytes: number }
  >();
  const limitations: string[] = [];
  for (const source of sources) {
    const keys = globalSymbolRegistryCandidateKeys(source.text);
    if (keys === undefined) {
      limitations.push(
        `${source.path}: Global-symbol companion linking is incomplete because candidate syntax could not be parsed; no unique publisher is inferred.`,
      );
      return { companions: new Map(), limitations };
    }
    const bytes = Buffer.byteLength(source.text);
    keyed.push({ source, keys, bytes });
    for (const key of keys) {
      const group = groups.get(key) ?? { sources: [], bytes: 0 };
      group.sources.push(source);
      group.bytes += bytes;
      groups.set(key, group);
    }
  }
  let retainedBytes = 0;
  const companions = new Map<string, readonly Source[]>();
  for (const { source, keys, bytes } of keyed) {
    // The sum conservatively charges duplicate candidates before allocating them.
    let offeredBytes = 0;
    for (const key of keys)
      offeredBytes += (groups.get(key)?.bytes ?? bytes) - bytes;
    if (offeredBytes > maximumCompanionBytes - retainedBytes) {
      limitations.push(
        `${source.path}: Global-symbol companion linking is incomplete: companion copies would exceed the artifact input-text budget of ${maximumCompanionBytes} bytes. No partial publisher set is used.`,
      );
      continue;
    }
    const selected = new Set<Source>();
    for (const key of keys)
      for (const candidate of groups.get(key)?.sources ?? [])
        if (candidate !== source) selected.add(candidate);
    companions.set(source.path, [...selected]);
    retainedBytes += offeredBytes;
  }
  return { companions, limitations };
};

const unbound = (
  node: t.Identifier,
  state: JavaScriptSemanticAnalysisState,
): boolean =>
  resolveSemanticBindingState(state, node, node.name) === undefined &&
  !semanticResolutionBlocked(state, node, node.name);
