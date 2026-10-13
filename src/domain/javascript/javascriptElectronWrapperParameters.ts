import * as t from "@babel/types";
import { javascriptBindingAliasComponents } from "./javascriptBindingAliases.js";

import type {
  ElectronApiIdentity,
  ElectronCalleeBinding,
} from "./electronStaticAnalysisTypes.js";
import { electronMemberPath } from "./javascriptElectronMemberWrites.js";
import {
  semanticStaticPropertyKey,
  unwrapJavaScriptExpression,
} from "./javascriptAstValues.js";
import { compositeKey } from "../unicodeCodePointOrder.js";
import { range } from "./javascriptStaticAnalysisHelpers.js";
import {
  resolveSemanticBindingState,
  semanticScopeId,
  semanticStableInitializer,
  type JavaScriptSemanticAnalysisState,
  type JavaScriptSemanticBindingState,
} from "./javascriptSemanticState.js";
import {
  childNodes,
  traverseJavaScriptAstSteps,
} from "./javascriptSemanticTraversal.js";

type WrapperIdentity = Extract<
  ElectronApiIdentity,
  { readonly basis: "wrapper-parameter" }
>;

/** One parameter position of a named function, with its destructuring keys. */
interface WrapperParameter {
  readonly wrapper: t.Function;
  readonly functionName: string;
  readonly functionBinding: JavaScriptSemanticBindingState;
  readonly parameter: string;
  readonly index: number;
  readonly projection: readonly string[];
  readonly fallback: t.Expression | undefined;
}

interface DeferredRoot {
  readonly root: t.Identifier;
  readonly members: readonly string[];
  readonly parameter: WrapperParameter;
  /** First argument of the deferred call, when it has one. */
  readonly channel: t.Node | undefined;
}

/** Call sites from which wrapper substitution can start, and whether the search finished. */
export interface WrapperEntries {
  readonly calls: readonly t.CallExpression[];
  /** False when WRAPPER_ENTRY_DEPTH stopped the search before every chain ended. */
  readonly complete: boolean;
}

// Electron IPC operation member names on ipcMain and ipcRenderer.
const IPC_OPERATIONS: ReadonlySet<string> = new Set([
  "addListener",
  "handle",
  "handleOnce",
  "invoke",
  "on",
  "once",
  "postMessage",
  "send",
  "sendSync",
  "sendToHost",
]);
// Bounds the backward search through forwarded wrapper parameters.
const WRAPPER_ENTRY_DEPTH = 8;

const parameterKey = ({ functionBinding, index }: WrapperParameter): string =>
  `${functionBinding.bindingId}:${String(index)}`;

/**
 * The named-wrapper parameter an argument forwards, `null` for a parameter
 * of an unnamed function, or `undefined` when the argument is not a
 * parameter and its call site is an entry.
 */
const forwardedParameter = (
  argument: t.CallExpression["arguments"][number] | undefined,
  state: JavaScriptSemanticAnalysisState,
  parameterFor: (
    root: t.Identifier,
    binding: JavaScriptSemanticBindingState,
  ) => WrapperParameter | undefined,
): WrapperParameter | null | undefined => {
  if (argument === undefined || !t.isExpression(argument)) return undefined;
  const { root } = electronMemberPath(argument);
  if (!t.isIdentifier(root)) return undefined;
  const binding = resolveSemanticBindingState(state, root, root.name);
  if (
    binding?.kind !== "parameter" ||
    binding.definitions.length !== 1 ||
    binding.definitions[0]?.kind !== "parameter"
  )
    return undefined;
  return parameterFor(root, binding) ?? null;
};

/** A named wrapper whose call sites replace inner calls that read its parameters. */
interface EnclosingSearch {
  readonly wrapper: t.Function;
  readonly functionName: string;
  readonly functionBinding: JavaScriptSemanticBindingState;
  readonly from: t.CallExpression[];
}

type EntrySearch = WrapperParameter | EnclosingSearch;

function* directCallSitesSteps(
  program: t.Program,
  state: JavaScriptSemanticAnalysisState,
  wrappers: readonly EntrySearch[],
): Generator<
  void,
  {
    readonly sites: ReadonlyMap<string, t.CallExpression[]>;
    readonly escaped: ReadonlySet<string>;
  }
> {
  const ids = new Set(
    wrappers.map(({ functionBinding }) => functionBinding.bindingId),
  );
  const names = new Set(wrappers.map(({ functionName }) => functionName));
  const sites = new Map<string, t.CallExpression[]>();
  const escaped = new Set<string>();
  yield* traverseJavaScriptAstSteps(program, {
    enter: (node) => {
      if (!t.isIdentifier(node) || !names.has(node.name)) return;
      const parent = state.parentsByNode.get(node);
      if (parent === undefined || !isReference(node, parent, state)) return;
      const binding = resolveSemanticBindingState(state, node, node.name);
      if (binding === undefined || !ids.has(binding.bindingId)) return;
      if (!t.isCallExpression(parent) || parent.callee !== node) {
        escaped.add(binding.bindingId);
        return;
      }
      const found = sites.get(binding.bindingId) ?? [];
      found.push(parent);
      sites.set(binding.bindingId, found);
    },
  });
  return { sites, escaped };
}

const enclosingFunctionOf = (
  node: t.Node,
  state: JavaScriptSemanticAnalysisState,
): t.Function | undefined => {
  let current = state.parentsByNode.get(node);
  while (current !== undefined && !t.isFunction(current))
    current = state.parentsByNode.get(current);
  return current;
};

/** The named wrapper function directly enclosing a call. */
const enclosingWrapper = (
  call: t.Node,
  state: JavaScriptSemanticAnalysisState,
): Omit<EnclosingSearch, "from"> | undefined => {
  const current = enclosingFunctionOf(call, state);
  if (current === undefined) return undefined;
  const named = wrapperName(current, state);
  return named === undefined
    ? undefined
    : {
        wrapper: current,
        functionName: named.name,
        functionBinding: named.binding,
      };
};

/** Whether call arguments, outside nested functions, read a wrapper's parameters. */
const readsParameters = (
  call: t.CallExpression,
  wrapper: t.Function,
  state: JavaScriptSemanticAnalysisState,
): boolean => {
  const scopeId = semanticScopeId("function", wrapper);
  const pending: t.Node[] = [...call.arguments];
  const visited = new Set<string>();
  while (pending.length > 0) {
    const node = pending.pop()!;
    if (t.isFunction(node)) continue;
    const parent = state.parentsByNode.get(node);
    if (
      t.isIdentifier(node) &&
      parent !== undefined &&
      isReference(node, parent, state)
    ) {
      const binding = resolveSemanticBindingState(state, node, node.name);
      if (binding?.kind === "parameter" && binding.scopeId === scopeId)
        return true;
      // Locals of the wrapper read the parameters their initializers read.
      const initializer =
        binding === undefined || visited.has(binding.bindingId)
          ? undefined
          : semanticStableInitializer(binding, state);
      if (
        binding !== undefined &&
        initializer !== undefined &&
        enclosingFunctionOf(initializer.node, state) === wrapper
      ) {
        visited.add(binding.bindingId);
        pending.push(initializer.node);
      }
    }
    pending.push(...childNodes(node));
  }
  return false;
};

interface ArgumentOutcome {
  readonly path: readonly string[] | undefined;
  readonly location: t.Node;
}

/**
 * Infer Electron API identity for callee roots that are local bindings whose
 * stable initializer is a `??`, `||`, `&&`, conditional, or object literal of
 * Electron values, and for roots that are parameters of one
 * named wrapper function. Only same-file direct calls are examined, and only
 * one wrapper level: argument expressions must be proven Electron exports, an
 * object literal member holding one, or a `??`, `||`, `&&` or conditional
 * branch of those. Every other argument stays an explicit unresolved count.
 *
 * This is a summary over all call sites. Symbolic call-path substitution binds
 * each call site's own arguments and reads this summary only for a parameter
 * that no call site on its path binds. The summary cannot reuse that
 * substitution: it belongs to the identity index the substitution reads, and
 * it records proving argument locations that substituted values do not carry.
 */
export const createElectronWrapperParameters = (
  state: JavaScriptSemanticAnalysisState,
  rootExport: (root: t.Node) => readonly string[] | undefined,
  memberWritten: ReadonlySet<string>,
) => {
  const aliases = javascriptBindingAliasComponents(state);
  const writtenBindings = new Set<string>();
  for (const bindingId of memberWritten)
    for (const alias of aliases.get(bindingId) ?? [bindingId])
      writtenBindings.add(alias);
  const deferred: DeferredRoot[] = [];
  const parameters = new Map<string, WrapperParameter | null>();
  const callSites = new Map<string, t.CallExpression["arguments"][]>();
  const escaped = new Set<string>();
  const locals: {
    readonly root: t.Identifier;
    readonly members: readonly string[];
    readonly initializer: t.Expression;
  }[] = [];

  const parameterFor = (
    root: t.Identifier,
    binding: JavaScriptSemanticBindingState,
  ): WrapperParameter | undefined => {
    const cached = parameters.get(binding.bindingId);
    if (cached !== undefined) return cached ?? undefined;
    const found = locateParameter(root, binding, state);
    parameters.set(binding.bindingId, found ?? null);
    return found;
  };

  return {
    /** Retain a call root whose identity may come from wrapper call sites. */
    defer: (
      root: t.Node,
      members: readonly (string | null)[],
      channel?: t.Node,
    ): void => {
      if (!t.isIdentifier(root)) return;
      if (!members.every((member): member is string => member !== null)) return;
      const binding = resolveSemanticBindingState(state, root, root.name);
      if (binding !== undefined && writtenBindings.has(binding.bindingId))
        return;
      const local = semanticStableInitializer(binding, state);
      const alternatives =
        local?.projection.length === 0
          ? unwrapJavaScriptExpression(local.node).node
          : undefined;
      if (
        t.isLogicalExpression(alternatives) ||
        t.isConditionalExpression(alternatives) ||
        t.isObjectExpression(alternatives)
      ) {
        locals.push({ root, members, initializer: alternatives });
        return;
      }
      if (
        binding?.kind !== "parameter" ||
        binding.definitions.length !== 1 ||
        binding.definitions[0]?.kind !== "parameter"
      )
        return;
      const parameter = parameterFor(root, binding);
      if (parameter !== undefined)
        deferred.push({ root, members, parameter, channel });
    },

    /** Collect direct calls and other references of the deferred wrappers. */
    *collectCallSitesSteps(program: t.Program): Generator<void> {
      if (deferred.length === 0) return;
      const wrappers = new Map<string, WrapperParameter>();
      for (const { parameter } of deferred)
        wrappers.set(parameter.functionBinding.bindingId, parameter);
      const names = new Set(
        [...wrappers.values()].map(({ functionName }) => functionName),
      );
      yield* traverseJavaScriptAstSteps(program, {
        enter: (node) => {
          if (!t.isIdentifier(node) || !names.has(node.name)) return;
          const parent = state.parentsByNode.get(node);
          if (parent === undefined || !isReference(node, parent, state)) return;
          const binding = resolveSemanticBindingState(state, node, node.name);
          if (binding === undefined) return;
          const wrapper = wrappers.get(binding.bindingId);
          if (wrapper === undefined) return;
          if (
            (t.isCallExpression(parent) || t.isNewExpression(parent)) &&
            parent.callee === node
          ) {
            const sites = callSites.get(binding.bindingId) ?? [];
            sites.push(parent.arguments);
            callSites.set(binding.bindingId, sites);
          } else escaped.add(binding.bindingId);
        },
      });
    },

    /**
     * Outermost same-file call sites of wrappers whose parameter receives an
     * IPC-named call with a computed channel. A call site whose argument is
     * itself a parameter of a named wrapper is followed to that wrapper's
     * call sites, at most WRAPPER_ENTRY_DEPTH levels deep.
     */
    *collectEntriesSteps(program: t.Program): Generator<void, WrapperEntries> {
      let frontier: EntrySearch[] = [];
      const parameters = new Set<string>();
      const enclosing = new Map<string, EnclosingSearch>();
      const followParameter = (
        parameter: WrapperParameter,
        next: EntrySearch[],
      ) => {
        const key = parameterKey(parameter);
        if (parameters.has(key)) return;
        parameters.add(key);
        next.push(parameter);
      };
      for (const { members, parameter, channel } of deferred)
        if (
          IPC_OPERATIONS.has(members.at(-1) ?? "") &&
          channel !== undefined &&
          !t.isStringLiteral(channel)
        )
          followParameter(parameter, frontier);
      const calls = new Set<t.CallExpression>();
      for (
        let depth = 0;
        depth < WRAPPER_ENTRY_DEPTH && frontier.length > 0;
        depth += 1
      ) {
        const { sites, escaped } = yield* directCallSitesSteps(
          program,
          state,
          frontier,
        );
        const next: EntrySearch[] = [];
        for (const search of frontier) {
          const found = sites.get(search.functionBinding.bindingId) ?? [];
          if (
            "from" in search &&
            (found.length === 0 ||
              escaped.has(search.functionBinding.bindingId))
          ) {
            // Callers of an escaping wrapper are unknown; its inner calls stay entries.
            for (const call of search.from) calls.add(call);
            continue;
          }
          for (const call of found) {
            const forwarded =
              "index" in search
                ? forwardedParameter(
                    call.arguments[search.index],
                    state,
                    parameterFor,
                  )
                : undefined;
            if (forwarded === null) continue;
            if (forwarded !== undefined) {
              followParameter(forwarded, next);
              continue;
            }
            // A call reading its enclosing wrapper's parameters is followed
            // to that wrapper's direct call sites.
            const wrapper = enclosingWrapper(call, state);
            if (
              wrapper === undefined ||
              !readsParameters(call, wrapper.wrapper, state)
            ) {
              calls.add(call);
              continue;
            }
            const existing = enclosing.get(wrapper.functionBinding.bindingId);
            if (existing !== undefined) existing.from.push(call);
            else {
              const search = { ...wrapper, from: [call] };
              enclosing.set(wrapper.functionBinding.bindingId, search);
              next.push(search);
            }
          }
        }
        frontier = next;
      }
      for (const search of frontier)
        if ("from" in search) for (const call of search.from) calls.add(call);
      return { calls: [...calls], complete: frontier.length === 0 };
    },

    /** Resolve each deferred root whose call-site arguments agree on one export. */
    *resolved(): Generator<{
      readonly root: t.Identifier;
      readonly binding: ElectronCalleeBinding;
    }> {
      for (const { root, members, initializer } of locals) {
        const outcomes = expressionOutcomes(initializer, members, rootExport);
        const proven = agreedOutcomes(outcomes);
        const [path] = proven;
        if (path === undefined) continue;
        yield {
          root,
          binding: {
            path: path.path,
            consumed_members: members.length,
            identity: {
              basis: "local-alternatives",
              binding: root.name,
              initializer_location: range(initializer),
              electron_value_locations: proven.map(({ location }) =>
                range(location),
              ),
              unresolved_values: outcomes.length - proven.length,
            },
          },
        };
      }
      for (const { root, members, parameter } of deferred) {
        const bindingId = parameter.functionBinding.bindingId;
        const sites = callSites.get(bindingId) ?? [];
        const wanted = [...parameter.projection, ...members];
        const outcomes = sites.flatMap((arguments_) =>
          argumentOutcomes(arguments_, parameter, wanted, rootExport),
        );
        const proven = agreedOutcomes(outcomes);
        const [path] = proven;
        if (path === undefined) continue;
        // The callee path is the resolved argument path; the callee members
        // already folded into it are consumed rather than appended again.
        const identity: WrapperIdentity = {
          basis: "wrapper-parameter",
          function_name: parameter.functionName,
          parameter: parameter.parameter,
          parameter_index: parameter.index,
          function_location: range(parameter.wrapper),
          call_sites: sites.length,
          call_sites_complete: !escaped.has(bindingId),
          electron_argument_locations: proven.map(({ location }) =>
            range(location),
          ),
          unresolved_arguments: outcomes.length - proven.length,
        };
        yield {
          root,
          binding: {
            path: path.path,
            consumed_members: members.length,
            identity,
          },
        };
      }
    },
  };
};

// Proven outcomes, only when they all name the same Electron export.
const agreedOutcomes = (
  outcomes: readonly ArgumentOutcome[],
): readonly (ArgumentOutcome & { readonly path: readonly string[] })[] => {
  const proven = outcomes.filter(
    (outcome): outcome is ArgumentOutcome & { path: readonly string[] } =>
      outcome.path !== undefined,
  );
  return new Set(proven.map(({ path }) => compositeKey(path))).size === 1
    ? proven
    : [];
};

const argumentOutcomes = (
  arguments_: t.CallExpression["arguments"],
  parameter: WrapperParameter,
  wanted: readonly string[],
  rootExport: (root: t.Node) => readonly string[] | undefined,
): readonly ArgumentOutcome[] => {
  const opaque = arguments_
    .slice(0, parameter.index + 1)
    .find((argument) => t.isSpreadElement(argument));
  if (opaque !== undefined) return [{ path: undefined, location: opaque }];
  const argument = arguments_[parameter.index];
  if (argument === undefined || t.isArgumentPlaceholder(argument))
    return parameter.fallback === undefined
      ? [{ path: undefined, location: parameter.wrapper }]
      : expressionOutcomes(parameter.fallback, wanted, rootExport);
  if (!t.isExpression(argument))
    return [{ path: undefined, location: argument }];
  return expressionOutcomes(argument, wanted, rootExport);
};

const expressionOutcomes = (
  node: t.Expression,
  wanted: readonly string[],
  rootExport: (root: t.Node) => readonly string[] | undefined,
): readonly ArgumentOutcome[] => {
  const expression = unwrapJavaScriptExpression(node).node;
  if (t.isLogicalExpression(expression))
    return [
      ...expressionOutcomes(expression.left, wanted, rootExport),
      ...expressionOutcomes(expression.right, wanted, rootExport),
    ];
  if (t.isConditionalExpression(expression))
    return [
      ...expressionOutcomes(expression.consequent, wanted, rootExport),
      ...expressionOutcomes(expression.alternate, wanted, rootExport),
    ];
  const [key, ...rest] = wanted;
  if (t.isObjectExpression(expression) && key !== undefined) {
    const member = objectLiteralMember(expression, key);
    return member === undefined
      ? [{ path: undefined, location: expression }]
      : expressionOutcomes(member, rest, rootExport);
  }
  const { root, members } = electronMemberPath(expression);
  const exported = members.every((member): member is string => member !== null)
    ? rootExport(root)
    : undefined;
  return [
    {
      path:
        exported === undefined
          ? undefined
          : [...exported, ...(members as readonly string[]), ...wanted],
      location: expression,
    },
  ];
};

// The effective value of one key in an object literal, when it is exact.
const objectLiteralMember = (
  object: t.ObjectExpression,
  key: string,
): t.Expression | undefined => {
  for (const property of object.properties.toReversed()) {
    if (t.isSpreadElement(property)) return undefined;
    const name = semanticStaticPropertyKey(property.key, property.computed);
    if (name === null) return undefined;
    if (name !== key) continue;
    return t.isObjectProperty(property) && t.isExpression(property.value)
      ? property.value
      : undefined;
  }
  return undefined;
};

const locateParameter = (
  root: t.Identifier,
  binding: JavaScriptSemanticBindingState,
  state: JavaScriptSemanticAnalysisState,
): WrapperParameter | undefined => {
  let current: t.Node | undefined = state.parentsByNode.get(root);
  while (
    current !== undefined &&
    !(
      t.isFunction(current) &&
      semanticScopeId("function", current) === binding.scopeId
    )
  )
    current = state.parentsByNode.get(current);
  if (current === undefined || !t.isFunction(current)) return undefined;
  const wrapper = current;
  const named = wrapperName(wrapper, state);
  if (named === undefined) return undefined;
  for (const [index, parameter] of wrapper.params.entries()) {
    const position = parameterPosition(parameter, binding.name);
    if (position !== undefined)
      return {
        wrapper,
        functionName: named.name,
        functionBinding: named.binding,
        parameter: binding.name,
        index,
        ...position,
      };
  }
  return undefined;
};

const parameterPosition = (
  parameter: t.Function["params"][number],
  name: string,
):
  | {
      readonly projection: readonly string[];
      readonly fallback: t.Expression | undefined;
    }
  | undefined => {
  if (t.isIdentifier(parameter))
    return parameter.name === name
      ? { projection: [], fallback: undefined }
      : undefined;
  if (t.isAssignmentPattern(parameter) && t.isIdentifier(parameter.left))
    return parameter.left.name === name
      ? { projection: [], fallback: parameter.right }
      : undefined;
  if (!t.isObjectPattern(parameter)) return undefined;
  for (const property of parameter.properties) {
    if (t.isRestElement(property)) continue;
    const key = semanticStaticPropertyKey(property.key, property.computed);
    if (key !== null && t.isIdentifier(property.value, { name }))
      return { projection: [key], fallback: undefined };
  }
  return undefined;
};

const wrapperName = (
  wrapper: t.Function,
  state: JavaScriptSemanticAnalysisState,
):
  | {
      readonly name: string;
      readonly binding: JavaScriptSemanticBindingState;
    }
  | undefined => {
  const declarator = state.parentsByNode.get(wrapper);
  const id = t.isFunctionDeclaration(wrapper)
    ? wrapper.id
    : t.isVariableDeclarator(declarator) && declarator.init === wrapper
      ? declarator.id
      : undefined;
  if (!t.isIdentifier(id)) return undefined;
  const binding = resolveSemanticBindingState(state, id, id.name);
  const initializer = semanticStableInitializer(binding, state);
  return binding !== undefined &&
    initializer?.node === wrapper &&
    initializer.projection.length === 0
    ? { name: id.name, binding }
    : undefined;
};

// Declaration identifiers and property keys are not references.
const isReference = (
  node: t.Identifier,
  parent: t.Node,
  state: JavaScriptSemanticAnalysisState,
): boolean => t.isReferenced(node, parent, state.parentsByNode.get(parent));
