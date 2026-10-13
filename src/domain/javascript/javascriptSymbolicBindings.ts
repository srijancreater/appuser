import * as t from "@babel/types";
import { javascriptBindingAliasComponents } from "./javascriptBindingAliases.js";
import {
  readExactJavaScriptLiteral,
  semanticStaticPropertyKey,
  semanticWriteTargets,
  unwrapJavaScriptExpression,
} from "./javascriptAstValues.js";
import { compositeKey } from "../unicodeCodePointOrder.js";
import type { JavaScriptSourceRange } from "./javascriptStaticAnalysisTypes.js";
import {
  foldSemanticOperands,
  isSemanticOperands,
  isSemanticOperatorExpression,
  SEMANTIC_OBJECT_OPERAND,
  type SemanticLeafOperand,
  type SemanticLeafOperands,
  type SemanticOperandFailure,
} from "./javascriptSemanticOperators.js";
import { javascriptBootstrapAt } from "./javascriptBootstrap.js";
import { createSemanticModuleInterop } from "./javascriptModuleInterop.js";
import { globalSymbolRegistryKey } from "./javascriptGlobalSymbolRegistry.js";
import { ELECTRON_MODULE } from "./javascriptElectronMemberWrites.js";
import {
  indexJavaScriptElectronIdentitySteps,
  type JavaScriptElectronIdentity,
} from "./javascriptSemanticAnalysis.js";
import {
  symbolicLoopHasExit,
  symbolicLogicalRight,
} from "./javascriptSymbolicControlFlow.js";
import {
  moduleFactory,
  modulePropertyName,
  range,
} from "./javascriptStaticAnalysisHelpers.js";
import {
  childNodes,
  completeSemanticSteps,
  traverseJavaScriptAst,
} from "./javascriptSemanticTraversal.js";
import {
  resolveSemanticBindingState,
  semanticResolutionBlocked,
  type JavaScriptSemanticAnalysisState,
} from "./javascriptSemanticState.js";
import {
  symbolicCondition,
  symbolicUnion,
  symbolicUnknown,
  symbolicVariants,
  symbolicConditionsUnresolved,
  symbolicTruth,
  isSymbolicObject,
  type SymbolicCondition,
  type SymbolicValue,
  type SymbolicEnvironment,
  type SymbolicFunction,
  type SymbolicMemberWrite,
} from "./javascriptSymbolicValues.js";

/** A value another source publishes under one global symbol registry key. */
export interface JavaScriptSymbolicLink {
  readonly resolver: JavaScriptSymbolicBindings;
  readonly value: t.Expression;
}

interface PropertyWrite {
  readonly path: readonly string[];
  readonly value: t.Node;
  readonly site: t.Node;
}
interface SymbolicReturnFlow {
  readonly values: readonly SymbolicValue[];
  readonly fallsThrough: boolean;
}
// Each operand variant multiplies the folded results; beyond this the value stays unknown.
const MAX_OPERAND_COMBINATIONS = 64;
// Module key under which a `__commonJS` require function holds its one module.
const COMMONJS_SELF = "";
const ARRAY_MUTATORS: ReadonlySet<string> = new Set([
  "copyWithin",
  "fill",
  "pop",
  "push",
  "reverse",
  "shift",
  "sort",
  "splice",
  "unshift",
]);
/** Demand-driven substitutions for local bindings, closures and literal module tables. */
export class JavaScriptSymbolicBindings {
  readonly #writes = new Map<string, PropertyWrite[]>();
  readonly #environments = new WeakMap<t.Node, SymbolicEnvironment>();
  readonly #cache = new WeakMap<
    SymbolicEnvironment,
    WeakMap<t.Node, SymbolicValue>
  >();
  readonly #active = new Set<t.Node>();
  readonly #activeFunctions = new Set<t.Function>();
  readonly #exportAliases = new Map<string, string>();
  readonly #moduleBindings = new Set<string>();
  readonly #replacements = new Map<string, t.Node>();
  readonly #propertyActive = new WeakMap<object, Set<string>>();
  readonly #literalPropertyIndex = new WeakMap<
    t.ObjectExpression,
    ReadonlyMap<string, t.ObjectMethod | t.ObjectProperty> | null
  >();
  readonly #mutated = new Set<string>();
  readonly #iterationWrites = new Map<
    string,
    {
      readonly key: t.Expression;
      readonly loop: t.ForOfStatement;
      readonly value: t.Node;
      readonly site: t.Node;
    }[]
  >();
  /** Loop-head declarations whose per-iteration value an environment substitutes. */
  readonly #iterationHeads = new Set<string>();
  readonly #electronIdentity: JavaScriptElectronIdentity;
  readonly #namespaceOwners = new Map<string, t.Function>();
  readonly #unsafeExports = new Set<string>();
  readonly #aliasComponents: ReadonlyMap<string, ReadonlySet<string>>;
  readonly #arrayAliasComponents = new WeakSet<ReadonlySet<string>>();
  readonly #invalidatedAliasComponents = new WeakSet<ReadonlySet<string>>();
  readonly #bootstrapTables: Array<{
    readonly tableAliases: ReadonlySet<string>;
    readonly modules: Map<string, SymbolicValue>;
  }> = [];
  readonly linkedSource: {
    readonly path: string;
    readonly text: string;
  } | null;
  #remainingEvaluations = 1_000_000;
  #evaluationFloor = 0;
  #dispatching = false;
  #shareExhausted = false;
  #depth = 0;
  truncated = false;
  unresolved = false;

  /** Root environment whose nodes belong to this source. */
  readonly #root: SymbolicEnvironment = { values: new Map(), owner: this };
  readonly #links: ReadonlyMap<string, JavaScriptSymbolicLink>;
  readonly #interop: ReturnType<typeof createSemanticModuleInterop>;
  /** Require functions returned by esbuild `__commonJS` wrapper calls. */
  readonly #commonJsRequires = new WeakMap<t.Node, SymbolicValue>();

  constructor(
    readonly state: JavaScriptSemanticAnalysisState,
    program: t.Program,
    electronIdentity = completeSemanticSteps(
      indexJavaScriptElectronIdentitySteps(program, state),
    ),
    options: {
      /** Values other sources publish under a global symbol registry key. */
      readonly links?: ReadonlyMap<string, JavaScriptSymbolicLink>;
      /** Artifact path and text of a linked source; absent for the analyzed source. */
      readonly linkedSource?: { readonly path: string; readonly text: string };
    } = {},
  ) {
    this.#links = options.links ?? new Map();
    this.linkedSource = options.linkedSource ?? null;
    this.#electronIdentity = electronIdentity;
    this.#aliasComponents = javascriptBindingAliasComponents(state);
    for (const binding of state.bindingsById.values()) {
      const aliases = this.#aliasComponents.get(binding.bindingId);
      if (
        aliases !== undefined &&
        binding.initializers.some((initializer) =>
          t.isArrayExpression(
            unwrapJavaScriptExpression(initializer.node).node,
          ),
        )
      )
        this.#arrayAliasComponents.add(aliases);
    }
    this.#interop = createSemanticModuleInterop(state);
    traverseJavaScriptAst(program, {
      enter: (node) => {
        if (!t.isCallExpression(node)) return;
        this.#indexBootstrap(node);
        this.#indexCommonJsWrapper(node);
      },
    });
    traverseJavaScriptAst(program, {
      enter: (node) => {
        if (t.isAssignmentExpression(node))
          this.#indexWrite(
            node.left,
            node.operator === "=" ? node.right : node,
            node,
          );
        if (t.isUpdateExpression(node))
          this.#indexWrite(node.argument, node, node);
        if (t.isUnaryExpression(node, { operator: "delete" }))
          this.#indexWrite(node.argument, node, node);
        // Array literals are exact only while no in-place mutator can reach them.
        if (t.isCallExpression(node) || t.isOptionalCallExpression(node)) {
          const callee = unwrapJavaScriptExpression(node.callee).node;
          if (
            t.isMemberExpression(callee) ||
            t.isOptionalMemberExpression(callee)
          ) {
            const receiver = unwrapJavaScriptExpression(callee.object).node;
            if (
              t.isIdentifier(receiver) &&
              ARRAY_MUTATORS.has(
                semanticStaticPropertyKey(callee.property, callee.computed) ??
                  "",
              )
            ) {
              const binding = resolveSemanticBindingState(
                state,
                receiver,
                receiver.name,
              );
              if (binding !== undefined)
                this.#invalidateAliases(
                  this.#aliasComponent(binding.bindingId),
                );
            }
          }
        }
        if (
          t.isCallExpression(node) &&
          t.isMemberExpression(node.callee) &&
          t.isIdentifier(node.callee.object, { name: "Object" }) &&
          !resolveSemanticBindingState(state, node.callee.object, "Object") &&
          semanticStaticPropertyKey(
            node.callee.property,
            node.callee.computed,
          ) === "defineProperty"
        ) {
          const [target, key, descriptor] = node.arguments;
          if (
            t.isIdentifier(target) &&
            t.isStringLiteral(key) &&
            t.isObjectExpression(descriptor)
          ) {
            const value = descriptor.properties.find(
              (p) =>
                t.isObjectProperty(p) &&
                semanticStaticPropertyKey(p.key, p.computed) === "value",
            );
            if (t.isObjectProperty(value))
              this.#addWrite(target, [key.value], value.value, node);
          }
        }
      },
    });
    for (const table of this.#bootstrapTables)
      this.#invalidateBootstrapTable(table.tableAliases, table.modules);
  }

  environmentAt(node: t.Node): SymbolicEnvironment {
    let current: t.Node | undefined = node;
    while (current) {
      const found = this.#environments.get(current);
      if (found) return found;
      current = this.state.parentsByNode.get(current);
    }
    return this.#root;
  }

  /** The resolver whose source owns the syntax of this environment. */
  ownerOf(
    environment: SymbolicEnvironment | undefined,
  ): JavaScriptSymbolicBindings {
    return environment?.owner instanceof JavaScriptSymbolicBindings
      ? environment.owner
      : this;
  }

  #valueOwner(value: SymbolicValue): JavaScriptSymbolicBindings {
    return value.kind === "object" ||
      value.kind === "namespace" ||
      value.kind === "function"
      ? this.ownerOf(value.environment)
      : this;
  }

  /**
   * Run one of `parts` remaining consumers with an equal share of the
   * remaining evaluations; returns whether that share was exhausted.
   */
  share(parts: number, run: () => void): boolean {
    const floor = this.#evaluationFloor;
    this.#evaluationFloor =
      this.#remainingEvaluations -
      Math.floor((this.#remainingEvaluations - floor) / parts);
    const before = this.#shareExhausted;
    this.#shareExhausted = false;
    try {
      run();
      return this.#shareExhausted;
    } finally {
      this.#remainingEvaluations = Math.max(
        this.#remainingEvaluations,
        this.#evaluationFloor,
      );
      this.#evaluationFloor = floor;
      this.#shareExhausted = before;
    }
  }

  evaluate(
    input: t.Node | null | undefined,
    environment?: SymbolicEnvironment,
  ): SymbolicValue {
    if (!input) return { kind: "literal", value: undefined };
    const owner = this.ownerOf(environment);
    if (owner !== this) return owner.evaluate(input, environment);
    if (--this.#remainingEvaluations < 0 || this.#depth >= 128) {
      this.truncated = true;
      return symbolicUnknown("symbolic resource limit");
    }
    if (this.#remainingEvaluations < this.#evaluationFloor) {
      this.#shareExhausted = true;
      return symbolicUnknown("symbolic resource share");
    }
    const node = unwrapJavaScriptExpression(input).node;
    const env = environment ?? this.environmentAt(node);
    const cache = this.#cache.get(env) ?? new WeakMap<t.Node, SymbolicValue>();
    this.#cache.set(env, cache);
    const cached = cache.get(node);
    if (cached) return cached;
    if (this.#active.has(node)) return symbolicUnknown("cyclic binding");
    this.#active.add(node);
    this.#depth += 1;
    try {
      const value = this.#evaluate(node, env);
      cache.set(node, value);
      return value;
    } finally {
      this.#active.delete(node);
      this.#depth -= 1;
    }
  }

  property(value: SymbolicValue, key: string): SymbolicValue {
    const owner = this.#valueOwner(value);
    if (owner !== this) return owner.property(value, key);
    let result: SymbolicValue;
    if (value.kind === "union")
      result = symbolicUnion(
        value.values.map((variant) => this.property(variant, key)),
      );
    else result = this.#property(value, key);
    for (const condition of value.conditions ?? [])
      result = symbolicCondition(result, condition);
    if (value.conditionUnresolved)
      result = symbolicConditionsUnresolved(result);
    return result;
  }

  #property(value: SymbolicValue, key: string): SymbolicValue {
    const active = this.#propertyActive.get(value) ?? new Set<string>();
    if (active.has(key)) return symbolicUnknown("cyclic property");
    active.add(key);
    this.#propertyActive.set(value, active);
    try {
      return this.#propertyValue(value, key);
    } finally {
      active.delete(key);
    }
  }

  #propertyValue(value: SymbolicValue, key: string): SymbolicValue {
    if (value.kind === "external") {
      const path = [...value.path, key];
      if (
        ELECTRON_MODULE.test(path[0] ?? "") &&
        !this.#electronIdentity.intactExport(path)
      ) {
        return symbolicUnknown("overwritten Electron API member");
      }
      return value.identity === undefined
        ? { kind: "external", path }
        : { kind: "external", path, identity: value.identity };
    }
    if (value.kind === "record")
      return value.values.get(key) ?? symbolicUnknown("missing property");
    if (value.kind === "namespace") {
      if (
        this.#mutated.has(value.bindingId) ||
        this.#unsafeExports.has(`${value.bindingId}:${key}`)
      )
        return symbolicUnknown("ambiguous export writes");
      const replacement = this.#replacements.get(value.bindingId);
      if (replacement)
        return this.property(
          this.evaluate(replacement, value.environment),
          key,
        );
      const writes = (this.#writes.get(value.bindingId) ?? []).filter(
        (w) => w.path.length === 1 && w.path[0] === key,
      );
      const write = writes.at(-1);
      return write
        ? this.evaluate(write.value, value.environment)
        : symbolicUnknown("unresolved module export");
    }
    if (value.kind === "object") {
      const written = this.#writtenMember(value, key);
      if (written !== undefined) return written;
      let index = this.#literalPropertyIndex.get(value.node);
      if (index === undefined) {
        const properties = new Map<string, t.ObjectMethod | t.ObjectProperty>();
        index = properties;
        for (const property of value.node.properties) {
          const name = t.isSpreadElement(property)
            ? null
            : semanticStaticPropertyKey(property.key, property.computed);
          if (name === null || t.isSpreadElement(property)) {
            index = null;
            break;
          }
          properties.set(name, property);
        }
        this.#literalPropertyIndex.set(value.node, index);
      }
      if (index !== null) {
        const property = index.get(key);
        if (property !== undefined)
          return this.#objectPropertyValue(property, value.environment);
        // A closed literal without the key reads `undefined` unless a write
        // may add it or the key names an inherited or prototype member.
        return key in Object.prototype ||
          index.has("__proto__") ||
          (value.writes !== undefined && this.unknownMembers(value) > 0)
          ? symbolicUnknown("missing property")
          : { kind: "literal", value: undefined };
      }
      for (const p of [...value.node.properties].reverse()) {
        if (t.isSpreadElement(p)) {
          const spread = this.evaluate(p.argument, value.environment);
          if (this.members(spread).includes(key))
            return this.property(spread, key);
          // Spreading nullish values copies nothing.
          if (
            !(spread.kind === "literal" && spread.value == null) &&
            this.unknownMembers(spread) > 0
          )
            return this.property(spread, key);
        } else if (semanticStaticPropertyKey(p.key, p.computed) === key) {
          return this.#objectPropertyValue(p, value.environment);
        } else if (semanticStaticPropertyKey(p.key, p.computed) === null)
          return symbolicUnknown("dynamic property overwrite");
      }
      return key in Object.prototype ||
        (value.writes !== undefined && this.unknownMembers(value) > 0)
        ? symbolicUnknown("missing property")
        : { kind: "literal", value: undefined };
    }
    if (value.kind === "array" && ARRAY_INDEX.test(key))
      return value.values[Number(key)] ?? symbolicUnknown("missing argument");
    return symbolicUnknown("unresolved property");
  }

  /** The value of the last completed write to this key, if one can apply. */
  #writtenMember(
    value: Extract<SymbolicValue, { kind: "object" }>,
    key: string,
  ): SymbolicValue | undefined {
    for (const write of [...(value.writes ?? [])].reverse()) {
      if (typeof write.key === "string") {
        if (write.key !== key) continue;
        const applies = this.#writeApplies(write, value.environment);
        if (applies === undefined)
          return symbolicUnknown("conditional member write");
        if (applies) return this.evaluate(write.value, value.environment);
        continue;
      }
      const iterations = this.#writeIterations(write, value.environment);
      if (iterations === undefined)
        return symbolicUnknown("dynamic loop writes");
      for (const { name, environment } of [...iterations].reverse()) {
        if (name !== key) continue;
        const applies = this.#writeApplies(write, environment);
        if (applies === undefined)
          return symbolicUnknown("conditional member write");
        if (applies) return this.evaluate(write.value, environment);
      }
    }
    return undefined;
  }

  /** Member names a loop write assigns, each with its iteration environment. */
  #writeIterations(
    write: SymbolicMemberWrite,
    environment: SymbolicEnvironment,
  ):
    | readonly {
        readonly name: string;
        readonly environment: SymbolicEnvironment;
      }[]
    | undefined {
    if (!("loop" in write) || symbolicLoopHasExit(write.loop)) return undefined;
    const iterable = this.evaluate(write.loop.right, environment);
    if (
      iterable.kind !== "array" ||
      iterable.conditions !== undefined ||
      iterable.conditionUnresolved
    )
      return undefined;
    const iterations = [];
    for (const element of iterable.values) {
      const iteration = this.bindIteration(write.loop, element, environment);
      if (iteration === undefined) return undefined;
      const name = this.evaluate(write.key, iteration);
      if (
        name.kind !== "literal" ||
        name.conditions !== undefined ||
        (typeof name.value !== "string" && typeof name.value !== "number")
      )
        return undefined;
      iterations.push({ name: String(name.value), environment: iteration });
    }
    return iterations;
  }

  #writeApplies(
    write: SymbolicMemberWrite,
    environment: SymbolicEnvironment,
  ): boolean | undefined {
    if (write.guard === undefined) return true;
    const right = symbolicLogicalRight(
      write.guard.operator,
      this.evaluate(write.guard.test, environment),
    );
    return right;
  }

  #objectPropertyValue(
    property: t.ObjectMethod | t.ObjectProperty,
    environment: SymbolicEnvironment,
  ): SymbolicValue {
    if (t.isObjectMethod(property) && property.kind === "get")
      return this.#invoke(
        { kind: "function", node: property, environment, origins: [] },
        [],
        property,
      );
    return t.isObjectMethod(property) && property.kind !== "method"
      ? symbolicUnknown("accessor property")
      : this.evaluate(
          t.isObjectProperty(property) ? property.value : property,
          environment,
        );
  }

  members(
    value: SymbolicValue,
    active = new Set<SymbolicValue>(),
  ): readonly string[] {
    const owner = this.#valueOwner(value);
    if (owner !== this) return owner.members(value, active);
    if (active.has(value)) return [];
    active.add(value);
    if (value.kind === "union")
      return [...new Set(value.values.flatMap((v) => this.members(v, active)))];
    if (value.kind === "record") return [...value.values.keys()];
    if (value.kind === "namespace") {
      const replacement = this.#replacements.get(value.bindingId);
      return replacement
        ? this.members(this.evaluate(replacement, value.environment), active)
        : [
            ...new Set(
              (this.#writes.get(value.bindingId) ?? []).flatMap((w) =>
                w.path.length === 1 ? w.path : [],
              ),
            ),
          ];
    }
    if (value.kind !== "object") return [];
    return [
      ...new Set([
        ...value.node.properties.flatMap((p) =>
          t.isSpreadElement(p)
            ? this.members(this.evaluate(p.argument, value.environment), active)
            : [semanticStaticPropertyKey(p.key, p.computed)].filter(
                (k): k is string => k !== null,
              ),
        ),
        ...(value.writes ?? []).flatMap((write) =>
          typeof write.key === "string"
            ? this.#writeApplies(write, value.environment) === true
              ? [write.key]
              : []
            : (this.#writeIterations(write, value.environment) ?? []).flatMap(
                ({ name, environment }) =>
                  this.#writeApplies(write, environment) === true ? [name] : [],
              ),
        ),
      ]),
    ];
  }

  unknownMembers(
    value: SymbolicValue,
    active = new Set<SymbolicValue>(),
  ): number {
    const owner = this.#valueOwner(value);
    if (owner !== this) return owner.unknownMembers(value, active);
    if (active.has(value)) return 1;
    active.add(value);
    if (value.kind === "union")
      return value.values.reduce(
        (sum, v) => sum + this.unknownMembers(v, active),
        0,
      );
    if (value.kind === "record") return 0;
    if (value.kind === "namespace") {
      if (this.#mutated.has(value.bindingId)) return 1;
      const replacement = this.#replacements.get(value.bindingId);
      return replacement
        ? this.unknownMembers(
            this.evaluate(replacement, value.environment),
            active,
          )
        : 0;
    }
    if (value.kind !== "object") return 1;
    const unknownWrites = (value.writes ?? []).reduce((sum, write) => {
      if (typeof write.key === "string")
        return (
          sum +
          Number(this.#writeApplies(write, value.environment) === undefined)
        );
      const iterations = this.#writeIterations(write, value.environment);
      return (
        sum +
        (iterations === undefined
          ? 1
          : iterations.filter(
              ({ environment }) =>
                this.#writeApplies(write, environment) === undefined,
            ).length)
      );
    }, 0);
    return (
      unknownWrites +
      value.node.properties.reduce(
        (sum, p) =>
          sum +
          (t.isSpreadElement(p)
            ? this.unknownMembers(
                this.evaluate(p.argument, value.environment),
                new Set(active),
              )
            : Number(semanticStaticPropertyKey(p.key, p.computed) === null)),
        0,
      )
    );
  }

  bind(
    fn: SymbolicFunction,
    args: readonly SymbolicValue[],
    invocationNode?: t.Node,
  ): SymbolicEnvironment {
    const owner = this.ownerOf(fn.environment);
    if (owner !== this) return owner.bind(fn, args, invocationNode);
    const values = new Map<string, SymbolicValue>();
    const scopeId =
      this.state.scopeByNode.get(fn.node)?.scopeId ??
      this.state.scopeByNode.get(fn.node.body)?.scopeId;
    const environment: SymbolicEnvironment = {
      values,
      parent: fn.environment,
      owner: this,
      point: invocationNode ?? fn.node,
      scopeNode: fn.node,
      ...(scopeId === undefined ? {} : { scopeId }),
    };
    fn.node.params.forEach((param, index) => {
      this.#bindPattern(
        t.isRestElement(param) ? param.argument : param,
        t.isRestElement(param)
          ? { kind: "array", values: args.slice(index) }
          : (args[index] ?? { kind: "literal", value: undefined }),
        values,
        environment,
      );
    });
    return environment;
  }

  /** Substitute one element of an exact iterable into a `for...of` declaration. */
  bindIteration(
    loop: t.ForOfStatement,
    element: SymbolicValue,
    parent: SymbolicEnvironment,
  ): SymbolicEnvironment | undefined {
    const owner = this.ownerOf(parent);
    if (owner !== this) return owner.bindIteration(loop, element, parent);
    if (
      !t.isVariableDeclaration(loop.left) ||
      loop.left.kind === "var" ||
      loop.left.declarations.length !== 1
    )
      return undefined;
    const pattern = loop.left.declarations[0]!.id;
    for (const target of semanticWriteTargets(pattern))
      if (t.isIdentifier(target)) {
        const binding = resolveSemanticBindingState(
          this.state,
          target,
          target.name,
        );
        if (binding)
          this.#iterationHeads.add(
            compositeKey([binding.bindingId, rangeKey(range(target))]),
          );
      }
    const values = new Map<string, SymbolicValue>();
    const environment: SymbolicEnvironment = { values, parent, owner: this };
    this.#bindPattern(pattern, element, values, environment);
    return environment;
  }

  /**
   * Bind the identifiers of one declaration or parameter pattern to the parts
   * of a value. Defaults apply only to an exactly `undefined` part.
   */
  #bindPattern(
    pattern: t.Node,
    value: SymbolicValue,
    values: Map<string, SymbolicValue>,
    environment: SymbolicEnvironment,
  ): void {
    const owner = this.ownerOf(environment);
    if (owner !== this) {
      owner.#bindPattern(pattern, value, values, environment);
      return;
    }
    if (t.isIdentifier(pattern)) {
      const binding = resolveSemanticBindingState(
        this.state,
        pattern,
        pattern.name,
      );
      if (binding) values.set(binding.bindingId, value);
      return;
    }
    if (t.isAssignmentPattern(pattern)) {
      const selected =
        value.kind === "literal" && value.value === undefined
          ? this.evaluate(pattern.right, environment)
          : value.kind === "unknown" || value.kind === "union"
            ? symbolicUnknown("runtime parameter")
            : value;
      this.#bindPattern(pattern.left, selected, values, environment);
      return;
    }
    if (t.isObjectPattern(pattern)) {
      for (const property of pattern.properties) {
        if (t.isRestElement(property)) {
          this.#bindPattern(
            property.argument,
            symbolicUnknown("object rest"),
            values,
            environment,
          );
          continue;
        }
        const key = semanticStaticPropertyKey(property.key, property.computed);
        this.#bindPattern(
          property.value,
          key === null
            ? symbolicUnknown("dynamic destructuring")
            : this.property(value, key),
          values,
          environment,
        );
      }
      return;
    }
    if (t.isArrayPattern(pattern))
      pattern.elements.forEach((element, index) => {
        if (element === null) return;
        if (t.isRestElement(element))
          this.#bindPattern(
            element.argument,
            value.kind === "array" && value.conditions === undefined
              ? { kind: "array", values: value.values.slice(index) }
              : symbolicUnknown("array rest"),
            values,
            environment,
          );
        else
          this.#bindPattern(
            element,
            this.property(value, String(index)),
            values,
            environment,
          );
      });
  }

  arguments(
    node: t.CallExpression | t.OptionalCallExpression,
    env: SymbolicEnvironment,
  ): readonly SymbolicValue[] {
    return node.arguments.flatMap((a) => {
      if (!t.isSpreadElement(a)) return [this.evaluate(a, env)];
      const value = this.evaluate(a.argument, env);
      return value.kind === "array"
        ? value.values
        : [symbolicUnknown("dynamic spread arguments")];
    });
  }

  #evaluate(node: t.Node, env: SymbolicEnvironment): SymbolicValue {
    const literal = readExactJavaScriptLiteral(node);
    if (literal.found) return { kind: "literal", value: literal.value };
    if (t.isFunction(node))
      return { kind: "function", node, environment: env, origins: [] };
    if (t.isObjectExpression(node))
      return { kind: "object", node, environment: env };
    if (t.isIdentifier(node)) return this.#identifier(node, env);
    if (t.isMemberExpression(node) || t.isOptionalMemberExpression(node)) {
      const registryKey = globalSymbolRegistryKey(node, this.state);
      if (registryKey !== undefined) {
        const link = this.#links.get(registryKey);
        return link === undefined
          ? symbolicUnknown("unlinked global symbol registry slot")
          : link.resolver.evaluate(link.value);
      }
      const key = semanticStaticPropertyKey(node.property, node.computed);
      // Array syntax has exact members only at its indices, so other reads
      // need not evaluate (and read bindings in) its elements.
      if (key !== null)
        return t.isArrayExpression(
          unwrapJavaScriptExpression(node.object).node,
        ) && !ARRAY_INDEX.test(key)
          ? symbolicUnknown("unresolved property")
          : this.property(this.evaluate(node.object, env), key);
      if (!node.computed || t.isPrivateName(node.property))
        return symbolicUnknown("dynamic member");
      const object = this.evaluate(node.object, env);
      return this.#combine([this.evaluate(node.property, env)], ([value]) =>
        value?.kind === "literal" &&
        (typeof value.value === "string" || typeof value.value === "number")
          ? this.property(object, String(value.value))
          : symbolicUnknown("dynamic member"),
      );
    }
    if (t.isSequenceExpression(node))
      return this.evaluate(node.expressions.at(-1), env);
    if (t.isAssignmentExpression(node))
      return node.operator === "="
        ? this.evaluate(node.right, env)
        : symbolicUnknown("compound assignment depends on its prior value");
    if (t.isAwaitExpression(node)) return this.evaluate(node.argument, env);
    // Negation reads truthiness, which objects and functions also have.
    if (t.isUnaryExpression(node, { operator: "!" })) {
      const truth = symbolicTruth(this.evaluate(node.argument, env));
      return truth === undefined
        ? symbolicUnknown("unresolved negation")
        : { kind: "literal", value: !truth };
    }
    if (t.isCallExpression(node) || t.isOptionalCallExpression(node)) {
      const called = this.#call(node, env);
      return called.kind === "unknown" && isSemanticOperatorExpression(node)
        ? this.#fold(node, env)
        : called;
    }
    if (isSemanticOperatorExpression(node)) return this.#fold(node, env);
    if (t.isConditionalExpression(node)) {
      const truth = symbolicTruth(this.evaluate(node.test, env));
      return truth === undefined
        ? symbolicUnion([
            symbolicCondition(this.evaluate(node.consequent, env), {
              node: node.test,
              positive: true,
              environment: env,
            }),
            symbolicCondition(this.evaluate(node.alternate, env), {
              node: node.test,
              positive: false,
              environment: env,
            }),
          ])
        : this.evaluate(truth ? node.consequent : node.alternate, env);
    }
    if (t.isLogicalExpression(node)) {
      const left = this.evaluate(node.left, env);
      const right = symbolicLogicalRight(node.operator, left);
      if (right !== undefined)
        return right ? this.evaluate(node.right, env) : left;
      const leftCondition: SymbolicCondition = {
        node: node.left,
        environment: env,
        positive:
          node.operator === "&&"
            ? false
            : node.operator === "||"
              ? true
              : "not-nullish",
      };
      const rightCondition: SymbolicCondition = {
        node: node.left,
        environment: env,
        positive:
          node.operator === "&&"
            ? true
            : node.operator === "||"
              ? false
              : "nullish",
      };
      return symbolicUnion([
        symbolicCondition(left, leftCondition),
        symbolicCondition(this.evaluate(node.right, env), rightCondition),
      ]);
    }
    if (t.isArrayExpression(node)) {
      const values: SymbolicValue[] = [];
      for (const element of node.elements) {
        if (element === null)
          values.push({ kind: "literal", value: undefined });
        else if (!t.isSpreadElement(element))
          values.push(this.evaluate(element, env));
        else {
          const spread = this.evaluate(element.argument, env);
          if (spread.kind !== "array" || spread.conditions !== undefined)
            return symbolicUnknown("dynamic array spread");
          values.push(...spread.values);
        }
      }
      return { kind: "array", values };
    }
    if (
      t.isNewExpression(node) &&
      t.isIdentifier(node.callee, { name: "Promise" }) &&
      resolveSemanticBindingState(this.state, node.callee, "Promise") ===
        undefined &&
      !semanticResolutionBlocked(this.state, node.callee, "Promise")
    )
      return { kind: "promise", node, fulfilled: false };
    return symbolicUnknown(`unsupported ${node.type}`);
  }

  /**
   * Apply one exact operation to every combination of operand variants,
   * keeping each variant's selection predicates on its result.
   */
  #combine(
    operands: readonly SymbolicValue[],
    operation: (variants: readonly SymbolicValue[]) => SymbolicValue,
  ): SymbolicValue {
    let combinations: SymbolicValue[][] = [[]];
    for (const operand of operands) {
      const variants = symbolicVariants(operand);
      if (combinations.length * variants.length > MAX_OPERAND_COMBINATIONS)
        return symbolicUnknown("operand combinations exceed the bound");
      combinations = combinations.flatMap((prefix) =>
        variants.map((variant) => [...prefix, variant]),
      );
    }
    return symbolicUnion(
      combinations.map((variants) => {
        let result = operation(
          variants.map(
            ({ conditions: _c, conditionUnresolved: _u, ...value }) =>
              value as SymbolicValue,
          ),
        );
        for (const variant of variants) {
          for (const condition of variant.conditions ?? [])
            result = symbolicCondition(result, condition);
          if (variant.conditionUnresolved)
            result = symbolicConditionsUnresolved(result);
        }
        return result;
      }),
    );
  }

  /**
   * Fold primitive operators with the constant lattice's operator semantics,
   * reading operands from this environment. An operand whose alternatives
   * carry selection predicates is folded once per alternative, so each result
   * keeps the predicates of the alternatives it was folded from.
   */
  #fold(node: t.Node, env: SymbolicEnvironment): SymbolicValue {
    const leaves = new Map<t.Node, SymbolicValue>();
    const read = (leaf: t.Node): SymbolicValue => {
      let value = leaves.get(leaf);
      if (value === undefined) {
        value = this.evaluate(leaf, env);
        leaves.set(leaf, value);
      }
      return value;
    };
    let folds = MAX_OPERAND_COMBINATIONS;
    const foldWith = (
      selected: ReadonlyMap<SymbolicValue, SymbolicValue>,
    ): SymbolicValue => {
      if (--folds < 0)
        return symbolicUnknown("operand combinations exceed the bound");
      let split: SymbolicValue | undefined;
      const unselected: SemanticOperandFailure = {
        status: "unknown",
        reason: "predicated operand",
      };
      const variantsOf = (
        value: SymbolicValue,
      ): readonly SymbolicValue[] | undefined => {
        const choice = selected.get(value);
        if (choice !== undefined) return [choice];
        const variants = symbolicVariants(value);
        if (
          variants.some(
            (variant) =>
              variant.conditions?.length || variant.conditionUnresolved,
          )
        ) {
          split ??= value;
          return undefined;
        }
        return variants;
      };
      const operands = (value: SymbolicValue): SemanticLeafOperands => {
        const variants = variantsOf(value);
        if (variants === undefined) return unselected;
        const values: SemanticLeafOperand[] = [];
        for (const variant of variants) {
          if (variant.kind === "literal") values.push(variant.value);
          else if (isSymbolicObject(variant))
            values.push(SEMANTIC_OBJECT_OPERAND);
          else
            return {
              status: "unknown",
              reason:
                variant.kind === "unknown"
                  ? variant.reason
                  : `${variant.kind} value is not a primitive`,
            };
        }
        return values;
      };
      const folded = foldSemanticOperands(
        node,
        {
          state: this.state,
          operands: (leaf) => operands(read(leaf)),
          arrayItems: (leaf) => {
            const variants = variantsOf(read(leaf));
            if (variants === undefined) return unselected;
            const array = variants.length === 1 ? variants[0] : undefined;
            if (array?.kind !== "array")
              return {
                status: "unknown",
                reason: "Join receiver is not an exact array.",
              };
            const items: (readonly SemanticLeafOperand[])[] = [];
            for (const item of array.values) {
              const values = operands(item);
              if (!isSemanticOperands(values)) return values;
              items.push(values);
            }
            return items;
          },
        },
        0,
      );
      if (split === undefined)
        return isSemanticOperands(folded)
          ? symbolicUnion(
              folded.map((value) => ({ kind: "literal" as const, value })),
            )
          : symbolicUnknown(folded.reason);
      const operand = split;
      return symbolicUnion(
        symbolicVariants(operand).map(
          ({ conditions, conditionUnresolved, ...exact }) => {
            let result = foldWith(
              new Map([...selected, [operand, exact as SymbolicValue]]),
            );
            for (const condition of conditions ?? [])
              result = symbolicCondition(result, condition);
            return conditionUnresolved
              ? symbolicConditionsUnresolved(result)
              : result;
          },
        ),
      );
    };
    return foldWith(new Map());
  }

  #identifier(node: t.Identifier, env: SymbolicEnvironment): SymbolicValue {
    const binding = resolveSemanticBindingState(this.state, node, node.name);
    if (
      !binding &&
      node.name === "undefined" &&
      !semanticResolutionBlocked(this.state, node, node.name)
    )
      return { kind: "literal", value: undefined };
    if (!binding)
      return !semanticResolutionBlocked(this.state, node, node.name) &&
        [
          "require",
          "navigator",
          "String",
          "Boolean",
          "Object",
          "Promise",
        ].includes(node.name)
        ? { kind: "external", path: [node.name] }
        : symbolicUnknown("unbound identifier");
    if (
      binding.definitions.some(
        (d) =>
          d.kind === "assignment" &&
          !this.#iterationHeads.has(
            compositeKey([binding.bindingId, rangeKey(d.location)]),
          ),
      )
    )
      return symbolicUnknown("reassigned binding");
    // Electron member identity is checked at the selected property. A write
    // to one method must not erase the module origin or unaffected siblings.
    const electronOrigin = this.#electronIdentity.exportPath(node);
    if (electronOrigin === undefined && this.#mutated.has(binding.bindingId))
      return symbolicUnknown("dynamic member writes");
    for (let e: SymbolicEnvironment | undefined = env; e; e = e.parent) {
      const value = e.values.get(binding.bindingId);
      if (value) return value;
    }
    const initializer =
      binding.initializers.length === 1 ? binding.initializers[0] : undefined;
    let writes: readonly SymbolicMemberWrite[] | undefined;
    if (
      electronOrigin === undefined &&
      (this.#writes.has(binding.bindingId) ||
        this.#iterationWrites.has(binding.bindingId))
    ) {
      writes =
        initializer !== undefined &&
        initializer.projection.length === 0 &&
        t.isObjectExpression(initializer.node)
          ? this.#localWrites(binding.bindingId, initializer.node, node)
          : undefined;
      if (writes === undefined)
        return symbolicUnknown("overwritten object members");
    }
    if (!initializer)
      return (
        (binding.initializers.length === 0
          ? this.#electronApi(node)
          : undefined) ?? symbolicUnknown("missing or ambiguous initializer")
      );
    const point = this.#initializerReadPoint(binding.scopeId, env, node);
    if (
      !initializer.entryBody &&
      !binding.definitions.every(({ kind }) => kind === "function") &&
      (initializer.node.end == null ||
        point == null ||
        initializer.node.end > point)
    ) {
      this.unresolved = true;
      return symbolicUnknown("initializer not available at this read");
    }
    if (this.state.conditionalInitializers.has(initializer.node))
      return symbolicUnknown("conditional initializer");
    let value = this.evaluate(
      initializer.node,
      this.#definingEnvironment(binding.scopeId, env),
    );
    if (writes !== undefined && value.kind === "object")
      return { ...value, environment: env, writes };
    for (const key of initializer.projection) {
      if (key === null) return symbolicUnknown("dynamic destructuring");
      value = this.property(value, String(key));
    }
    return value;
  }

  /**
   * The activation that declared a binding, so readers in nested activations
   * share one evaluation of its initializer. Loop substitutions between the
   * reader and that activation keep the reader's environment.
   */
  #definingEnvironment(
    bindingScopeId: string,
    environment: SymbolicEnvironment,
  ): SymbolicEnvironment {
    for (
      let current: SymbolicEnvironment | undefined = environment;
      current;
      current = current.parent
    ) {
      if (current.scopeId === undefined)
        return current === this.#root && current.parent === undefined
          ? current
          : environment;
      if (this.#scopeContains(bindingScopeId, current.scopeId)) return current;
    }
    return environment;
  }

  /**
   * Electron identity of an import or unbound parameter read, owned by the
   * shared identity index. An import keeps its module binding. A parameter
   * the walk did not bind at a call site uses the wrapper-parameter or
   * local-alternatives inference over its function's direct call sites, which
   * the index records only for call roots.
   */
  #electronApi(node: t.Identifier): SymbolicValue | undefined {
    const exported = this.#electronIdentity.exportPath(node);
    if (exported !== undefined)
      return { kind: "external", path: ["electron", ...exported] };
    const callee = this.#electronIdentity.callees.get(node.start ?? -1);
    if (callee === undefined || callee.identity.basis === "module-binding")
      return undefined;
    return {
      kind: "external",
      path: [
        "electron",
        ...callee.path.slice(0, callee.path.length - callee.consumed_members),
      ],
      identity: callee.identity,
    };
  }

  #initializerReadPoint(
    bindingScopeId: string,
    environment: SymbolicEnvironment,
    readNode: t.Node,
  ): number | undefined {
    let current: SymbolicEnvironment | undefined = environment;
    let child: SymbolicEnvironment | undefined;
    while (current) {
      if (this.#scopeContains(bindingScopeId, current.scopeId)) {
        const point = child?.point ?? readNode;
        if (current.completedAt !== undefined)
          return current.completedAt.end ?? undefined;
        if (
          this.#dispatching &&
          current.scopeNode !== undefined &&
          !current.scopeNode.async &&
          !current.scopeNode.generator
        )
          return current.scopeNode.end ?? undefined;
        if (current.scopeNode && !this.#nodeWithin(point, current.scopeNode))
          return undefined;
        return point.start ?? undefined;
      }
      child = current;
      current = current.parent;
    }
    if (this.#dispatching) return Number.MAX_SAFE_INTEGER;
    let outermost = environment;
    while (outermost.parent) outermost = outermost.parent;
    const point = outermost.point ?? environment.point ?? readNode;
    return point.start ?? undefined;
  }

  #scopeContains(bindingScopeId: string, environmentScopeId?: string): boolean {
    let scopeId: string | null = bindingScopeId;
    while (scopeId !== null) {
      if (scopeId === environmentScopeId) return true;
      scopeId = this.state.scopesById.get(scopeId)?.parentScopeId ?? null;
    }
    return false;
  }

  #nodeWithin(node: t.Node, ancestor?: t.Node): boolean {
    if (!ancestor) return false;
    let current: t.Node | undefined = node;
    while (current) {
      if (current === ancestor) return true;
      current = this.state.parentsByNode.get(current);
    }
    return false;
  }

  /**
   * Evaluate as code dispatched later from the event loop: activations are
   * complete at their end, except suspended async or generator ones.
   */
  dispatch(run: () => void): void {
    const previous = this.#dispatching;
    this.#dispatching = true;
    try {
      run();
    } finally {
      this.#dispatching = previous;
    }
  }

  #completedEnvironment(
    environment: SymbolicEnvironment,
    activation: SymbolicEnvironment,
    returnPoint: t.Node,
  ): SymbolicEnvironment | undefined {
    if (environment === activation)
      return { ...environment, completedAt: returnPoint };
    if (environment.parent === undefined) return undefined;
    const parent = this.#completedEnvironment(
      environment.parent,
      activation,
      returnPoint,
    );
    return parent === undefined ? undefined : { ...environment, parent };
  }

  #completeReturnedFunction(
    value: SymbolicFunction,
    activation: SymbolicEnvironment,
    returnPoint: t.Node,
  ): SymbolicFunction {
    const environment = this.#completedEnvironment(
      value.environment,
      activation,
      returnPoint,
    );
    if (environment === undefined) return value;
    const { returnPoint: _returnPoint, ...returned } = value;
    return { ...returned, environment };
  }

  #moduleCompletionPoint(factory: t.Function): t.Node {
    let earliestReturn: t.ReturnStatement | undefined;
    const pending: t.Node[] = [factory.body];
    while (pending.length > 0) {
      const node = pending.pop();
      if (!node) continue;
      if (node !== factory.body && (t.isFunction(node) || t.isClass(node)))
        continue;
      if (
        t.isReturnStatement(node) &&
        (earliestReturn === undefined ||
          (node.start ?? Infinity) < (earliestReturn.start ?? Infinity))
      )
        earliestReturn = node;
      pending.push(...childNodes(node));
    }
    return earliestReturn ?? factory.body;
  }

  #invoke(
    fn: SymbolicFunction,
    args: readonly SymbolicValue[],
    node: t.Node,
  ): SymbolicValue {
    if (this.#activeFunctions.has(fn.node))
      return symbolicUnknown("recursive call");
    this.#activeFunctions.add(fn.node);
    try {
      const bound = this.bind(fn, args, node);
      const returned = t.isBlockStatement(fn.node.body)
        ? this.#returns(fn.node.body.body, bound)
        : this.evaluate(fn.node.body, bound);
      return symbolicUnion(
        symbolicVariants(returned).map((v) => {
          if (v.kind === "function")
            return {
              ...this.#completeReturnedFunction(
                v,
                bound,
                v.returnPoint ?? fn.node.body,
              ),
              origins: [...fn.origins, node, ...v.origins],
            };
          // Members of a returned literal read the activation after it returned.
          if (v.kind === "object" && v.writes === undefined) {
            const environment = this.#completedEnvironment(
              v.environment,
              bound,
              fn.node.body,
            );
            return environment === undefined ? v : { ...v, environment };
          }
          return v;
        }),
      );
    } finally {
      this.#activeFunctions.delete(fn.node);
    }
  }

  /**
   * A proven ESM namespace conversion copies the module's own members;
   * `default` is the module itself in node mode and otherwise unresolved.
   */
  #convertedNamespace(
    module: SymbolicValue,
    defaultIsModule: boolean,
  ): SymbolicValue {
    if (this.unknownMembers(module) > 0)
      return symbolicUnknown("dynamic converted namespace");
    const values = new Map<string, SymbolicValue>();
    for (const key of this.members(module))
      if (key !== "default") values.set(key, this.property(module, key));
    values.set(
      "default",
      defaultIsModule ? module : symbolicUnknown("converted default export"),
    );
    return { kind: "record", values };
  }

  /** Call an exact function once per element of an exact array. */
  #mapArray(
    array: SymbolicValue,
    callback: SymbolicValue,
    node: t.Node,
  ): SymbolicValue {
    if (array.kind !== "array" || callback.kind !== "function")
      return symbolicUnknown("dynamic array callback");
    return {
      kind: "array",
      values: array.values.map((element, index) =>
        this.#invoke(
          callback,
          [element, { kind: "literal", value: index }, array],
          node,
        ),
      ),
    };
  }

  #call(
    node: t.CallExpression | t.OptionalCallExpression,
    env: SymbolicEnvironment,
  ): SymbolicValue {
    const commonJs = this.#commonJsRequires.get(node);
    if (commonJs !== undefined) return commonJs;
    const conversion = this.#interop.namespaceConversion(node);
    if (conversion !== undefined)
      return this.#convertedNamespace(
        this.evaluate(conversion.input, env),
        conversion.defaultIsModule,
      );
    // Arguments are read only for callees that consume them, so reads in
    // calls of unresolved callees do not mark the substitution unresolved.
    let args: readonly SymbolicValue[] | undefined;
    const callArguments = () => (args ??= this.arguments(node, env));
    const callee = node.callee;
    if (
      (t.isMemberExpression(callee) || t.isOptionalMemberExpression(callee)) &&
      semanticStaticPropertyKey(callee.property, callee.computed) === "map"
    ) {
      const receiver = this.evaluate(callee.object, env);
      if (receiver.kind === "array" && receiver.conditions === undefined)
        return this.#combine(
          [callArguments()[0] ?? symbolicUnknown("missing callback")],
          ([fn]) => this.#mapArray(receiver, fn!, node),
        );
    }
    return this.#callValue(node, this.evaluate(callee, env), callArguments);
  }

  #callValue(
    node: t.CallExpression | t.OptionalCallExpression,
    callee: SymbolicValue,
    callArguments: () => readonly SymbolicValue[],
  ): SymbolicValue {
    return symbolicUnion(
      symbolicVariants(callee).map((value) => {
        let result: SymbolicValue;
        if (value.kind === "loader") {
          const actual = callArguments();
          const key =
            actual.length === 0
              ? { kind: "literal" as const, value: COMMONJS_SELF }
              : actual[0];
          const loaded =
            key?.kind === "literal"
              ? (value.modules.get(String(key.value)) ??
                symbolicUnknown("missing module"))
              : symbolicUnknown("dynamic module");
          if (loaded.kind === "namespace") {
            const factory = this.#namespaceOwners.get(loaded.bindingId);
            result =
              factory === undefined
                ? loaded
                : {
                    ...loaded,
                    environment: {
                      ...loaded.environment,
                      completedAt: this.#moduleCompletionPoint(factory),
                    },
                  };
          } else result = loaded;
        } else if (
          value.kind === "external" &&
          value.path.join(".") === "require"
        ) {
          const spec = callArguments()[0];
          result =
            spec?.kind === "literal" && typeof spec.value === "string"
              ? { kind: "external", path: [spec.value] }
              : symbolicUnknown("dynamic require");
        } else if (value.kind === "external" && value.path[0] === "Object")
          result = objectBuiltin(
            this,
            value.path.slice(1).join("."),
            callArguments(),
          );
        else if (
          value.kind === "external" &&
          value.path.join(".") === "Promise.resolve"
        ) {
          const [settled] = callArguments();
          // A non-object value cannot be a thenable, so the promise is fulfilled.
          result =
            settled === undefined || settled.kind === "literal"
              ? { kind: "promise", node, fulfilled: true }
              : symbolicUnknown("unresolved call");
        } else if (value.kind === "function")
          result = this.#invoke(value, callArguments(), node);
        else result = symbolicUnknown("unresolved call");
        for (const condition of value.conditions ?? [])
          result = symbolicCondition(result, condition);
        if (value.conditionUnresolved)
          result = symbolicConditionsUnresolved(result);
        return result;
      }),
    );
  }

  #returns(
    statements: readonly t.Statement[],
    env: SymbolicEnvironment,
  ): SymbolicValue {
    const flow = this.#returnFlow(statements, env);
    return symbolicUnion([
      ...flow.values,
      ...(flow.fallsThrough
        ? [{ kind: "literal" as const, value: undefined }]
        : []),
    ]);
  }

  #returnFlow(
    statements: readonly t.Statement[],
    env: SymbolicEnvironment,
    depth = 0,
  ): SymbolicReturnFlow {
    const possible: SymbolicValue[] = [];
    let unresolvedFallthrough = false;
    const continuationConditions: SymbolicCondition[] = [];
    const guardCurrentPath = (value: SymbolicValue): SymbolicValue => {
      let guarded = value;
      for (const condition of continuationConditions)
        guarded = symbolicCondition(guarded, condition);
      return unresolvedFallthrough
        ? symbolicConditionsUnresolved(guarded)
        : guarded;
    };
    for (const statement of statements) {
      if (--this.#remainingEvaluations < 0 || depth >= 128) {
        this.truncated = true;
        return {
          values: [...possible, symbolicUnknown("symbolic resource limit")],
          fallsThrough: false,
        };
      }
      if (t.isThrowStatement(statement))
        return {
          values: [...possible, symbolicUnknown("wrapper exits by throwing")],
          fallsThrough: false,
        };
      if (t.isReturnStatement(statement)) {
        const value = this.evaluate(statement.argument, env);
        const returned = symbolicUnion(
          symbolicVariants(value).map((variant) =>
            variant.kind === "function"
              ? { ...variant, returnPoint: statement }
              : variant,
          ),
        );
        return {
          values: [...possible, guardCurrentPath(returned)],
          fallsThrough: false,
        };
      }
      if (t.isBlockStatement(statement)) {
        const flow = this.#returnFlow(statement.body, env, depth + 1);
        possible.push(...flow.values.map(guardCurrentPath));
        if (!flow.fallsThrough)
          return { values: possible, fallsThrough: false };
      }
      if (t.isIfStatement(statement)) {
        const truth = symbolicTruth(this.evaluate(statement.test, env));
        const branches =
          truth === undefined
            ? [statement.consequent, statement.alternate]
            : [truth ? statement.consequent : statement.alternate];
        const flows = branches.map((branch) =>
          this.#returnFlow(branch ? [branch] : [], env, depth + 1),
        );
        possible.push(
          ...flows.flatMap((flow, index) =>
            flow.values.map((value) => {
              const guarded = guardCurrentPath(value);
              return truth === undefined
                ? symbolicCondition(guarded, {
                    node: statement.test,
                    positive: index === 0,
                    environment: env,
                  })
                : guarded;
            }),
          ),
        );
        if (flows.every((flow) => !flow.fallsThrough))
          return { values: possible, fallsThrough: false };
        if (truth === undefined) {
          const fallthrough = flows.flatMap((flow, index) =>
            flow.fallsThrough ? [{ flow, index }] : [],
          );
          if (
            fallthrough.length === 1 &&
            fallthrough[0]?.flow.values.length === 0
          )
            continuationConditions.push({
              node: statement.test,
              positive: fallthrough[0].index === 0,
              environment: env,
            });
          else if (
            fallthrough.length > 0 &&
            (fallthrough.length < flows.length ||
              fallthrough.some(({ flow }) => flow.values.length > 0))
          )
            unresolvedFallthrough = true;
        }
      }
    }
    return { values: possible, fallsThrough: true };
  }

  #indexBootstrap(call: t.CallExpression): void {
    const bootstrap = javascriptBootstrapAt(call, this.state);
    if (!bootstrap) return;
    const modules = new Map<string, SymbolicValue>();
    const tableAliases = this.#aliasComponent(bootstrap.tableBindingId);
    for (const property of bootstrap.table.properties) {
      const factory = moduleFactory(property);
      if (!factory) continue;
      const [module, exports, loader] = factory.params;
      const { namespace, values } = this.#registerModuleFactory(
        factory,
        module,
        exports,
      );
      const loaderId = t.isIdentifier(loader)
        ? resolveSemanticBindingState(this.state, loader, loader.name)
            ?.bindingId
        : undefined;
      if (loaderId) values.set(loaderId, { kind: "loader", modules });
      modules.set(modulePropertyName(property), namespace);
    }
    this.#bootstrapTables.push({ tableAliases, modules });
  }

  /**
   * Give one module factory an exports namespace bound to its `module` and
   * `exports` parameters, so their writes define the namespace.
   */
  #registerModuleFactory(
    factory: t.Function,
    module: t.Node | undefined,
    exports: t.Node | undefined,
  ): {
    readonly namespace: SymbolicValue;
    readonly values: Map<string, SymbolicValue>;
  } {
    const values = new Map<string, SymbolicValue>();
    const scopeId = this.state.scopeByNode.get(factory)?.scopeId;
    const environment: SymbolicEnvironment = {
      values,
      owner: this,
      point: factory.body,
      scopeNode: factory,
      ...(scopeId === undefined ? {} : { scopeId }),
    };
    const binding = (n: t.Node | undefined) =>
      t.isIdentifier(n)
        ? resolveSemanticBindingState(this.state, n, n.name)?.bindingId
        : undefined;
    const moduleId = binding(module);
    const exportsId = binding(exports);
    const namespaceId = `${String(factory.start)}:exports`;
    this.#namespaceOwners.set(namespaceId, factory);
    const namespace: SymbolicValue = {
      kind: "namespace",
      bindingId: namespaceId,
      environment,
    };
    if (moduleId) {
      values.set(moduleId, {
        kind: "record",
        values: new Map([["exports", namespace]]),
      });
      this.#exportAliases.set(moduleId, namespaceId);
      this.#moduleBindings.add(moduleId);
    }
    if (exportsId) {
      values.set(exportsId, namespace);
      this.#exportAliases.set(exportsId, namespaceId);
    }
    this.#environments.set(factory, environment);
    return { namespace, values };
  }

  /** esbuild `__commonJS(factory)`: a require function for one lazily evaluated factory. */
  #indexCommonJsWrapper(call: t.CallExpression): void {
    const factory = this.#interop.commonJsFactory(call);
    if (factory === undefined) return;
    const [exports, module] = factory.params;
    const { namespace } = this.#registerModuleFactory(factory, module, exports);
    this.#commonJsRequires.set(call, {
      kind: "loader",
      modules: new Map([[COMMONJS_SELF, namespace]]),
    });
  }

  #aliasComponent(bindingId: string): ReadonlySet<string> {
    return this.#aliasComponents.get(bindingId) ?? new Set([bindingId]);
  }

  #arrayAliasComponent(bindingId: string): ReadonlySet<string> | undefined {
    const aliases = this.#aliasComponents.get(bindingId);
    return aliases !== undefined && this.#arrayAliasComponents.has(aliases)
      ? aliases
      : undefined;
  }

  #invalidateAliases(aliases: ReadonlySet<string>): void {
    if (this.#invalidatedAliasComponents.has(aliases)) return;
    this.#invalidatedAliasComponents.add(aliases);
    for (const id of aliases) this.#mutated.add(id);
  }

  #invalidateBootstrapTable(
    tableAliases: ReadonlySet<string>,
    modules: Map<string, SymbolicValue>,
  ): void {
    let invalidateAll = false;
    const invalidSlots = new Set<string>();
    for (const bindingId of tableAliases) {
      if (this.#mutated.has(bindingId)) invalidateAll = true;
      for (const definition of this.state.bindingsById.get(bindingId)
        ?.definitions ?? [])
        if (definition.kind === "assignment") invalidateAll = true;
      for (const write of this.#writes.get(bindingId) ?? []) {
        if (write.path.length === 0) invalidateAll = true;
        else invalidSlots.add(write.path[0]!);
      }
    }
    if (invalidateAll) modules.clear();
    else for (const key of invalidSlots) modules.delete(key);
  }

  #indexWrite(target: t.Node, value: t.Node, site: t.Node): void {
    const path: string[] = [];
    let root = unwrapJavaScriptExpression(target).node;
    let dynamic = false;
    while (t.isMemberExpression(root) || t.isOptionalMemberExpression(root)) {
      const key = semanticStaticPropertyKey(root.property, root.computed);
      if (key === null) dynamic = true;
      else path.unshift(key);
      root = unwrapJavaScriptExpression(root.object).node;
    }
    if (dynamic && t.isIdentifier(root)) {
      const binding = resolveSemanticBindingState(this.state, root, root.name);
      if (!binding) return;
      const arrayAliases = this.#arrayAliasComponent(binding.bindingId);
      if (arrayAliases !== undefined) {
        this.#invalidateAliases(arrayAliases);
        return;
      }
      const key =
        t.isAssignmentExpression(site, { operator: "=" }) &&
        t.isMemberExpression(target) &&
        target.object === root &&
        t.isExpression(target.property) &&
        !this.#exportAliases.has(binding.bindingId)
          ? target.property
          : undefined;
      const loop = key === undefined ? undefined : this.#iterationKeyLoop(key);
      if (key !== undefined && loop !== undefined) {
        const writes = this.#iterationWrites.get(binding.bindingId) ?? [];
        writes.push({ key, loop, value, site });
        this.#iterationWrites.set(binding.bindingId, writes);
      } else
        this.#mutated.add(
          this.#exportAliases.get(binding.bindingId) ?? binding.bindingId,
        );
      return;
    }
    if (t.isIdentifier(root)) this.#addWrite(root, path, value, site);
  }

  /** The enclosing `for...of` in the same function whose declaration binds this key. */
  #iterationKeyLoop(key: t.Node): t.ForOfStatement | undefined {
    if (!t.isIdentifier(key)) return undefined;
    const binding = resolveSemanticBindingState(this.state, key, key.name);
    if (!binding) return undefined;
    for (
      let parent = this.state.parentsByNode.get(key);
      parent && !t.isFunction(parent);
      parent = this.state.parentsByNode.get(parent)
    )
      if (
        t.isForOfStatement(parent) &&
        t.isVariableDeclaration(parent.left) &&
        parent.left.kind !== "var" &&
        parent.left.declarations.length === 1 &&
        [...semanticWriteTargets(parent.left.declarations[0]!.id)].some(
          (target) =>
            t.isIdentifier(target) &&
            resolveSemanticBindingState(this.state, target, target.name)
              ?.bindingId === binding.bindingId,
        )
      )
        return parent;
    return undefined;
  }

  /**
   * Writes to a fresh local object literal that all complete before this
   * read: direct statements of its declaring function, optionally the right
   * operand of one short-circuit test, or loop writes keyed by an iterated
   * declaration. Any other write leaves the object unresolved.
   */
  #localWrites(
    bindingId: string,
    initializer: t.Node,
    read: t.Node,
  ): readonly SymbolicMemberWrite[] | undefined {
    const owner = this.#enclosingFunction(initializer);
    const writes: (SymbolicMemberWrite & { readonly site: t.Node })[] = [];
    for (const write of this.#writes.get(bindingId) ?? []) {
      const key = write.path.length === 1 ? write.path[0] : undefined;
      if (
        key === undefined ||
        !t.isAssignmentExpression(write.site, { operator: "=" })
      )
        return undefined;
      writes.push({ key, value: write.value, site: write.site });
    }
    for (const write of this.#iterationWrites.get(bindingId) ?? [])
      writes.push({
        key: write.key,
        loop: write.loop,
        value: write.value,
        site: write.site,
      });
    const ordered: SymbolicMemberWrite[] = [];
    for (const write of writes.sort(
      (a, b) => (a.site.start ?? 0) - (b.site.start ?? 0),
    )) {
      if (this.#enclosingFunction(write.site) !== owner) return undefined;
      const boundary = "loop" in write ? write.loop : write.site;
      if (
        this.#nodeWithin(read, owner) &&
        (read.start ?? 0) < (boundary.end ?? Infinity)
      )
        return undefined;
      const top = owner === undefined ? undefined : owner.body;
      let guard: SymbolicMemberWrite["guard"];
      let child: t.Node = write.site;
      for (
        let parent = this.state.parentsByNode.get(child);
        parent !== top && !t.isProgram(parent);
        child = parent, parent = this.state.parentsByNode.get(child)
      ) {
        if (parent === undefined) return undefined;
        if ("loop" in write && parent === write.loop) {
          // Only a loop that runs once per activation of its owner.
          const container = this.state.parentsByNode.get(parent);
          if (container !== top && !t.isProgram(container)) return undefined;
          break;
        }
        if (
          t.isExpressionStatement(parent) ||
          t.isReturnStatement(parent) ||
          t.isSequenceExpression(parent) ||
          ("loop" in write && parent === write.loop.body)
        )
          continue;
        if (
          t.isLogicalExpression(parent) &&
          child === parent.right &&
          guard === undefined
        ) {
          guard = { test: parent.left, operator: parent.operator };
          continue;
        }
        return undefined;
      }
      const { site: _site, ...member } = write;
      ordered.push(guard === undefined ? member : { ...member, guard });
    }
    return ordered;
  }

  #enclosingFunction(node: t.Node): t.Function | undefined {
    for (
      let parent = this.state.parentsByNode.get(node);
      parent;
      parent = this.state.parentsByNode.get(parent)
    )
      if (t.isFunction(parent)) return parent;
    return undefined;
  }

  #addWrite(
    root: t.Identifier,
    path: readonly string[],
    value: t.Node,
    site: t.Node,
  ): void {
    const binding = resolveSemanticBindingState(this.state, root, root.name);
    if (!binding) return;
    const arrayAliases =
      path.length === 0
        ? undefined
        : this.#arrayAliasComponent(binding.bindingId);
    if (arrayAliases !== undefined) this.#invalidateAliases(arrayAliases);
    const alias = this.#exportAliases.get(binding.bindingId);
    if (this.#moduleBindings.has(binding.bindingId) && path[0] !== "exports")
      return;
    const key = alias ?? binding.bindingId;
    const selected = this.#moduleBindings.has(binding.bindingId)
      ? path.slice(1)
      : path;
    if (alias) {
      const owner = this.#namespaceOwners.get(alias);
      for (
        let parent = this.state.parentsByNode.get(site);
        parent && parent !== owner;
        parent = this.state.parentsByNode.get(parent)
      ) {
        if (
          t.isFunction(parent) ||
          t.isIfStatement(parent) ||
          t.isConditionalExpression(parent) ||
          t.isLogicalExpression(parent) ||
          t.isLoop(parent) ||
          t.isSwitchCase(parent) ||
          t.isTryStatement(parent)
        ) {
          if (selected.length === 0) this.#mutated.add(key);
          else this.#unsafeExports.add(`${key}:${selected[0] ?? ""}`);
          return;
        }
      }
    }
    if (alias && selected.length === 0) {
      this.#replacements.set(key, value);
      return;
    }
    const writes = this.#writes.get(key) ?? [];
    writes.push({ path: selected, value, site });
    this.#writes.set(key, writes);
  }
}

const rangeKey = ({ start, end }: JavaScriptSourceRange): string =>
  `${String(start.line)}:${String(start.column)}-${String(end.line)}:${String(end.column)}`;

const ARRAY_INDEX = /^(?:0|[1-9]\d*)$/u;

/** Model the `Object` builtins that read own enumerable keys of an exact object. */
const objectBuiltin = (
  resolver: JavaScriptSymbolicBindings,
  name: string,
  args: readonly SymbolicValue[],
): SymbolicValue => {
  const [target] = args;
  if (target === undefined) return symbolicUnknown("missing Object argument");
  if (name === "freeze") return target;
  if (name !== "entries" && name !== "keys" && name !== "values")
    return symbolicUnknown(`unmodeled Object.${name}`);
  if (
    !["object", "record", "namespace"].includes(target.kind) ||
    resolver.unknownMembers(target) > 0
  )
    return symbolicUnknown("dynamic object keys");
  const {
    conditions: _conditions,
    conditionUnresolved: _unresolved,
    ...rest
  } = target;
  const exact = rest as SymbolicValue;
  const members = resolver.members(exact);
  // Own string keys enumerate integer-like keys first, then insertion order.
  const keys = [
    ...members
      .filter((key) => ARRAY_INDEX.test(key))
      .sort((left, right) => Number(left) - Number(right)),
    ...members.filter((key) => !ARRAY_INDEX.test(key)),
  ];
  let result: SymbolicValue = {
    kind: "array",
    values: keys.map((key): SymbolicValue => {
      const literal: SymbolicValue = { kind: "literal", value: key };
      if (name === "keys") return literal;
      const value = resolver.property(exact, key);
      return name === "values"
        ? value
        : { kind: "array", values: [literal, value] };
    }),
  };
  for (const condition of target.conditions ?? [])
    result = symbolicCondition(result, condition);
  return target.conditionUnresolved
    ? symbolicConditionsUnresolved(result)
    : result;
};
