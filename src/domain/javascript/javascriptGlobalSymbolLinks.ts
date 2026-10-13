import * as t from "@babel/types";

import {
  globalSymbolRegistryKey,
  globalSymbolRegistryPublications,
} from "./javascriptGlobalSymbolRegistry.js";
import {
  indexJavaScriptBindingsSteps,
  indexJavaScriptElectronIdentitySteps,
} from "./javascriptSemanticAnalysis.js";
import type { JavaScriptSemanticAnalysisState } from "./javascriptSemanticState.js";
import { traverseJavaScriptAstSteps } from "./javascriptSemanticTraversal.js";
import { parseJavaScriptSource } from "./javascriptSourceParser.js";
import {
  JavaScriptSymbolicBindings,
  type JavaScriptSymbolicLink,
} from "./javascriptSymbolicBindings.js";

/** Another source of the same artifact that may share this source's realm. */
export interface JavaScriptCompanionSource {
  readonly path: string;
  readonly text: string;
}

/**
 * Link each global symbol registry key this source reads, and does not
 * publish itself, to the one companion that publishes it at load. Companions
 * are parsed only when their text names a key this source reads; a key
 * published by several companions, or more than once, stays unlinked.
 */
export function* linkJavaScriptGlobalSymbolRegistrySteps(
  program: t.Program,
  state: JavaScriptSemanticAnalysisState,
  companions: readonly JavaScriptCompanionSource[],
): Generator<void, ReadonlyMap<string, JavaScriptSymbolicLink>> {
  const links = new Map<string, JavaScriptSymbolicLink>();
  if (companions.length === 0) return links;
  const own = globalSymbolRegistryPublications(program, state);
  const read = new Set<string>();
  yield* traverseJavaScriptAstSteps(program, {
    enter: (node) => {
      const key = globalSymbolRegistryKey(node, state);
      if (key !== undefined && !own.has(key)) read.add(key);
    },
  });
  const publishers = new Map<string, (JavaScriptSymbolicLink | null)[]>();
  for (const companion of companions) {
    const parsed = parseJavaScriptSource(companion.text, companion.path);
    yield;
    if (parsed === null) continue;
    const companionState = yield* indexJavaScriptBindingsSteps(parsed.program);
    const published = globalSymbolRegistryPublications(
      parsed.program,
      companionState,
    );
    const keys = [...read].filter((key) => published.has(key));
    if (keys.length === 0) continue;
    const resolver = new JavaScriptSymbolicBindings(
      companionState,
      parsed.program,
      yield* indexJavaScriptElectronIdentitySteps(
        parsed.program,
        companionState,
      ),
      { linkedSource: { path: companion.path, text: companion.text } },
    );
    for (const key of keys) {
      const value = published.get(key);
      publishers.set(key, [
        ...(publishers.get(key) ?? []),
        value === undefined || value === null ? null : { resolver, value },
      ]);
    }
  }
  for (const [key, found] of publishers) {
    const [link] = found;
    if (found.length === 1 && link !== undefined && link !== null)
      links.set(key, link);
  }
  return links;
}
