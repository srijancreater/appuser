import type { JavaScriptSemanticEvidenceContextRegistry } from "../../domain/javascript/javascriptSemanticGraph.js";
import type {
  JavaScriptSemanticGraphNode,
  JavaScriptSemanticGraphUnknown,
} from "../../domain/javascript/javascriptSemanticGraphSchemas.js";

interface SemanticFact {
  readonly evidence: { readonly context_id: string };
}

const serializedBytes = (value: unknown): number =>
  Buffer.byteLength(JSON.stringify(value));

/**
 * Serialized Evidence bytes one source file's semantic facts may occupy.
 *
 * The projection emits facts per expression, binding, call and property slot;
 * one 527 KB vendor bundle projects 236 MB of facts. The owning projection
 * admits facts in projection order until the first refusal closes the file,
 * so a truncated file keeps a source-ordered prefix of its passes. Nodes wait
 * here until an admitted fact references them; unknown frontiers wait until
 * every relation was offered. Omitted facts are counted exactly. A
 * caller-selected node capacity closes admission the same way.
 */
export class SemanticFileGraphBudget {
  readonly limit: number | null;
  /** Caller-selected node capacity of this file; null when none was selected. */
  readonly nodeLimit: number | null;
  #used = 0;
  #nodes = 0;
  #closed = false;
  readonly #chargedContexts = new Set<string>();
  readonly #omittedNodes = new Set<string>();
  readonly #omittedRelations = new Set<string>();
  /** Constructed nodes not yet referenced by an admitted fact, in creation order. */
  readonly pendingNodes = new Map<string, JavaScriptSemanticGraphNode>();
  /** Unknown frontiers offered after every node relation. */
  readonly deferredUnknowns = new Map<string, JavaScriptSemanticGraphUnknown>();

  /** A null limit admits every fact and still measures its serialized size. */
  constructor(limit: number | null, nodeLimit: number | null = null) {
    for (const value of [limit, nodeLimit])
      if (value !== null && (!Number.isSafeInteger(value) || value < 0))
        throw new RangeError(
          "Semantic file graph budget must be a nonnegative safe integer",
        );
    this.limit = limit;
    this.nodeLimit = nodeLimit;
  }

  /** Whether a refused fact closed admission for this file. */
  get closed(): boolean {
    return this.#closed;
  }

  /** Serialized bytes of every admitted fact and its first-referenced context. */
  get used(): number {
    return this.#used;
  }

  /** Charge one fact with the provenance context it references first. */
  admit(
    fact: SemanticFact,
    contexts: JavaScriptSemanticEvidenceContextRegistry,
  ): boolean {
    if (this.#closed) return false;
    const contextId = fact.evidence.context_id;
    const newContext = !this.#chargedContexts.has(contextId);
    const bytes =
      serializedBytes(fact) +
      (newContext ? serializedBytes(contexts.context(contextId)) : 0);
    if (this.limit !== null && this.#used + bytes > this.limit) {
      this.#closed = true;
      return false;
    }
    this.#used += bytes;
    if (newContext) this.#chargedContexts.add(contextId);
    return true;
  }

  /** Charge one node against the node capacity and the byte budget. */
  admitNode(
    node: SemanticFact,
    contexts: JavaScriptSemanticEvidenceContextRegistry,
  ): boolean {
    if (this.nodeLimit !== null && this.#nodes >= this.nodeLimit)
      this.#closed = true;
    if (!this.admit(node, contexts)) return false;
    this.#nodes += 1;
    return true;
  }

  omitNode(nodeId: string): void {
    this.#omittedNodes.add(nodeId);
  }

  omitRelation(relationId: string): void {
    this.#omittedRelations.add(relationId);
  }

  /** Distinct node identities that were constructed or requested but not admitted. */
  get omittedNodes(): number {
    return this.#omittedNodes.size;
  }

  /** Distinct relations refused although they were constructed. */
  get omittedRelations(): number {
    return this.#omittedRelations.size;
  }

  /** Whether one interned context is referenced by an admitted fact. */
  references(contextId: string): boolean {
    return this.#chargedContexts.has(contextId);
  }
}
