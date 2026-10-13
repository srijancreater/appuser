import type * as t from "@babel/types";

import type { ElectronApiIdentity } from "./electronStaticAnalysisTypes.js";

/** A lexical substitution environment, never a JavaScript execution context. */
export interface SymbolicEnvironment {
  readonly values: ReadonlyMap<string, SymbolicValue>;
  readonly parent?: SymbolicEnvironment;
  /** Source point at which the current function is being symbolically executed. */
  readonly point?: t.Node;
  /** Lexical function scope for point-sensitive local initializer checks. */
  readonly scopeId?: string;
  /** Function activation captured by this environment, when one exists. */
  readonly scopeNode?: t.Function;
  /** Completion boundary proven for this captured activation. */
  readonly completedAt?: t.Node;
  /**
   * The resolver of the source that owns this environment's syntax, when it
   * is not the evaluating source. Linked sources keep their own bindings.
   */
  readonly owner?: object;
}

export interface SymbolicCondition {
  readonly node: t.Node;
  readonly positive: boolean | "nullish" | "not-nullish";
  /** The activation that evaluated the predicate, when one is known. */
  readonly environment?: SymbolicEnvironment;
}

export interface SymbolicMetadata {
  /** Predicates required for this value to be selected. */
  readonly conditions?: readonly SymbolicCondition[];
  /** A control-flow join prevented a sound predicate from being retained. */
  readonly conditionUnresolved?: true;
}

/**
 * One ordered write to a member of a fresh local object literal. A static key
 * names one member; a loop write assigns the member named by its `for...of`
 * declaration once per iterated element.
 */
export type SymbolicMemberWrite = {
  readonly value: t.Node;
  /** Short-circuit test the write is the right operand of, if any. */
  readonly guard?: {
    readonly test: t.Node;
    readonly operator: t.LogicalExpression["operator"];
  };
} & (
  | { readonly key: string }
  | { readonly key: t.Expression; readonly loop: t.ForOfStatement }
);

export interface SymbolicFunction extends SymbolicMetadata {
  readonly kind: "function";
  readonly node: t.Function;
  readonly environment: SymbolicEnvironment;
  readonly origins: readonly t.Node[];
  /** Return statement completing the activation that produced this value. */
  readonly returnPoint?: t.Node;
}

export type SymbolicValue = (
  | { readonly kind: "unknown"; readonly reason: string }
  | {
      readonly kind: "literal";
      readonly value: string | number | boolean | null | undefined;
    }
  | {
      readonly kind: "external";
      readonly path: readonly string[];
      /** Inferred Electron identity; absent for a proven module origin. */
      readonly identity?: ElectronApiIdentity;
    }
  | {
      readonly kind: "object";
      readonly node: t.ObjectExpression;
      readonly environment: SymbolicEnvironment;
      /** Member writes completed on this fresh local literal before the read. */
      readonly writes?: readonly SymbolicMemberWrite[];
    }
  | {
      readonly kind: "namespace";
      readonly bindingId: string;
      readonly environment: SymbolicEnvironment;
    }
  | {
      readonly kind: "loader";
      readonly modules: ReadonlyMap<string, SymbolicValue>;
    }
  | { readonly kind: "array"; readonly values: readonly SymbolicValue[] }
  | {
      readonly kind: "record";
      readonly values: ReadonlyMap<string, SymbolicValue>;
    }
  | { readonly kind: "union"; readonly values: readonly SymbolicValue[] }
  | {
      readonly kind: "promise";
      /** Expression creating the promise. */
      readonly node: t.Node;
      /** Whether it is created fulfilled; otherwise its settlement is unknown. */
      readonly fulfilled: boolean;
    }
  | SymbolicFunction
) &
  SymbolicMetadata;

export const symbolicUnknown = (reason: string): SymbolicValue => ({
  kind: "unknown",
  reason,
});
export const symbolicVariants = (
  value: SymbolicValue,
): readonly SymbolicValue[] =>
  value.kind === "union" ? value.values : [value];
export const symbolicUnion = (
  values: readonly SymbolicValue[],
): SymbolicValue => {
  const unique = [...new Set(values.flatMap(symbolicVariants))];
  return unique.length === 1 ? unique[0]! : { kind: "union", values: unique };
};
export const symbolicTruth = (value: SymbolicValue): boolean | undefined => {
  if (value.kind === "union") {
    const choices = value.values.map(symbolicTruth);
    return choices.length > 0 &&
      choices.every((choice) => choice === choices[0])
      ? choices[0]
      : undefined;
  }
  return value.kind === "literal"
    ? Boolean(value.value)
    : isSymbolicObject(value)
      ? true
      : undefined;
};

const OBJECT_KINDS: ReadonlySet<SymbolicValue["kind"]> = new Set([
  "function",
  "object",
  "namespace",
  "array",
  "record",
  "loader",
  "promise",
]);

/** Whether a value is a JavaScript object (functions and promises included). */
export const isSymbolicObject = (value: SymbolicValue): boolean =>
  OBJECT_KINDS.has(value.kind);

/** Attach selection predicates to values while preserving their representation. */
export const symbolicCondition = (
  value: SymbolicValue,
  condition: SymbolicCondition,
): SymbolicValue => {
  if (value.kind === "union")
    return symbolicUnion(
      value.values.map((variant) => symbolicCondition(variant, condition)),
    );
  return { ...value, conditions: [...(value.conditions ?? []), condition] };
};

export const symbolicConditionsUnresolved = (
  value: SymbolicValue,
): SymbolicValue => {
  if (value.kind === "union")
    return symbolicUnion(value.values.map(symbolicConditionsUnresolved));
  return { ...value, conditionUnresolved: true };
};
