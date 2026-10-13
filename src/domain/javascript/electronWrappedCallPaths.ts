import * as t from "@babel/types";
import {
  JavaScriptSymbolicBindings,
  type JavaScriptSymbolicLink,
} from "./javascriptSymbolicBindings.js";
import {
  symbolicVariants,
  symbolicTruth,
  symbolicUnknown,
  type SymbolicValue,
  type SymbolicEnvironment,
  type SymbolicFunction,
} from "./javascriptSymbolicValues.js";
import type { JavaScriptSemanticAnalysisState } from "./javascriptSemanticState.js";
import type { JavaScriptElectronIdentity } from "./javascriptSemanticAnalysis.js";
import type { JavaScriptAnalysisAccumulator } from "./javascriptStaticAnalysisState.js";
import type {
  ElectronApiIdentity,
  ElectronCallPath,
  ElectronCallPathStep,
  ElectronContextBridgeFinding,
  ElectronIpcDescriptor,
  ElectronIpcFinding,
  ElectronStaticValue,
} from "./electronStaticAnalysisTypes.js";
import {
  contextBridgeExposureArguments,
  type JavaScriptContextBridgeExposureArguments,
} from "./javascriptContextBridgeExposure.js";
import { boundedExpression } from "./electronStaticAnalysisValues.js";
import { sha256Text, argumentNode } from "./javascriptStaticAnalysisHelpers.js";
import {
  childNodes,
  traverseJavaScriptAst,
} from "./javascriptSemanticTraversal.js";
import { range, calleeName } from "./javascriptStaticAnalysisHelpers.js";
import { semanticStaticPropertyKey } from "./javascriptAstValues.js";
import { ipcDescriptor } from "./electronStaticAnalysisIpc.js";
import {
  symbolicDefiniteExit,
  symbolicLoopHasExit,
  symbolicLogicalRight,
} from "./javascriptSymbolicControlFlow.js";

// Nesting depth of exposed API members traced through plain objects.
const MAX_EXPOSED_MEMBER_DEPTH = 8;

const callLabel = (node: t.Node): string =>
  t.isSequenceExpression(node)
    ? callLabel(node.expressions.at(-1) ?? node)
    : calleeName(node) || "local call";

type GuardPolarity = boolean | "nullish" | "not-nullish" | "fulfilled";

/** One branch predicate, tied to the activation that evaluated it when known. */
interface PathGuard {
  readonly node: t.Node;
  readonly positive: GuardPolarity;
  readonly environment: SymbolicEnvironment | null;
  readonly condition: ElectronCallPath["conditions"][number];
}

interface PathContext {
  readonly entryNode: t.Node;
  readonly entry: string;
  readonly entryKind: ElectronCallPath["entry_kind"] | null;
  readonly channel: string | null;
  readonly steps: readonly ElectronCallPathStep[];
  readonly conditions: ElectronCallPath["conditions"];
  /** The predicates of `conditions`, in the same order. */
  readonly guards: readonly PathGuard[];
  /** Latest call of this source on the path; it locates linked operations. */
  readonly local: t.Node;
  readonly active: ReadonlySet<t.Function>;
}

/** An IPC operation reached through substitution under each listed guard conjunction. */
interface PendingIpcFinding {
  readonly offset: number;
  readonly finding: ElectronIpcFinding;
  readonly alternatives: (readonly PathGuard[])[];
}

/** Substitutes inert wrapper syntax; every emitted path remains a candidate. */
export const collectElectronWrappedCallPaths = (
  program: t.Program,
  state: JavaScriptSemanticAnalysisState,
  source: string,
  accumulator: JavaScriptAnalysisAccumulator,
  identity: JavaScriptElectronIdentity,
  links: ReadonlyMap<string, JavaScriptSymbolicLink> = new Map(),
): readonly ElectronCallPath[] => {
  // Bounds repeated interprocedural expansion independently of bundle bytes.
  // Exhaustion is reported as unknown coverage, never as a negative finding.
  let remainingVisits = 1_000_000;
  // Visits below this floor belong to handler bodies not yet traced.
  let visitFloor = 0;
  let handlerBudgetReached = false;
  const resolver = new JavaScriptSymbolicBindings(state, program, identity, {
    links,
  });
  const linked = [...new Set([...links.values()].map((link) => link.resolver))];
  const linkedDigests = new Map(
    linked.flatMap((other) =>
      other.linkedSource === null
        ? []
        : [
            [
              other.linkedSource.path,
              sha256Text(other.linkedSource.text),
            ] as const,
          ],
    ),
  );
  /** The linked source owning this syntax; null for this source. */
  const linkedSourceOf = (
    node: t.Node,
  ): { readonly path: string; readonly text: string } | null =>
    state.parentsByNode.has(node) || node === program
      ? null
      : (linked.find((other) => other.state.parentsByNode.has(node))
          ?.linkedSource ?? null);
  const sourcePathOf = (node: t.Node): string | null =>
    linkedSourceOf(node)?.path ?? null;
  const paths: ElectronCallPath[] = [];
  const seen = new Set<string>();
  const pendingIpc = new Map<string, PendingIpcFinding>();
  const handlerBodies: (() => void)[] = [];
  const step = (
    node: t.Node,
    kind: ElectronCallPathStep["kind"],
    label: string,
  ): ElectronCallPathStep => {
    const sourcePath = sourcePathOf(node);
    if (sourcePath !== null)
      return {
        kind,
        label,
        location: range(node),
        module_key: null,
        module_runtime: null,
        source_path: sourcePath,
        source_sha256: linkedDigests.get(sourcePath)!,
      };
    const module = accumulator.moduleRangeIndex.find(node.start);
    return {
      kind,
      label,
      location: range(node),
      module_key: module?.key ?? null,
      module_runtime: module?.runtime ?? null,
    };
  };
  const condition = (
    context: PathContext,
    node: t.Node,
    positive: GuardPolarity = true,
    environment: SymbolicEnvironment | null = null,
  ): PathContext => {
    const owner = linkedSourceOf(node);
    const expression = (owner?.text ?? source)
      .slice(node.start ?? 0, node.end ?? 0)
      .slice(0, 512);
    const predicate = {
      expression:
        positive === "fulfilled"
          ? `(${expression}) is fulfilled`
          : positive === "nullish"
            ? `(${expression}) === null || (${expression}) === undefined`
            : positive === "not-nullish"
              ? `(${expression}) !== null && (${expression}) !== undefined`
              : positive
                ? expression
                : `!(${expression})`,
      location: range(node),
      ...(owner === null ? {} : { source_path: owner.path }),
    };
    return {
      ...context,
      guards: [
        ...context.guards,
        { node, positive, environment, condition: predicate },
      ],
      conditions: [...context.conditions, predicate],
    };
  };

  const metadataContext = (
    context: PathContext,
    value: SymbolicValue,
  ): PathContext | null => {
    if (value.conditionUnresolved) {
      accumulator.unknownFindings += 1;
      return null;
    }
    return (
      value.conditions?.reduce(
        (current, branch) =>
          condition(
            current,
            branch.node,
            branch.positive,
            branch.environment ?? null,
          ),
        context,
      ) ?? context
    );
  };
  const hasConditions = (value: SymbolicValue): boolean =>
    symbolicVariants(value).some((variant) => variant.conditions?.length);
  const isolatedBridgeCall = (
    node: t.CallExpression | t.OptionalCallExpression,
  ):
    | { readonly env: SymbolicEnvironment; readonly callee: SymbolicValue }
    | undefined => {
    const env = resolver.environmentAt(node);
    const callee = resolver.evaluate(node.callee, env);
    return symbolicVariants(callee).some(
      (callee) =>
        callee.kind === "external" &&
        identity.intactExport(callee.path) &&
        callee.path.slice(1).join(".") ===
          "contextBridge.exposeInIsolatedWorld",
    )
      ? { env, callee }
      : undefined;
  };
  const electronStaticSymbolicValue = (
    value: SymbolicValue | undefined,
    node: t.Node | undefined,
  ): ElectronStaticValue => {
    const variants = value === undefined ? [] : symbolicVariants(value);
    const variant = variants.length === 1 ? variants[0] : undefined;
    if (variant?.kind === "literal" && variant.value !== undefined)
      return {
        status: "literal",
        value: variant.value,
        expression: null,
      };
    return {
      status: "dynamic",
      value: null,
      expression: boundedExpression(source, node),
    };
  };
  const emit = (
    context: PathContext,
    node: t.Node,
    terminal: string,
    channel = context.channel,
  ): void => {
    if (context.entryKind === null) return;
    const path: ElectronCallPath = {
      entry_kind: context.entryKind,
      entry: context.entry,
      channel,
      terminal,
      resolution: "candidate",
      steps: [...context.steps, step(node, "terminal", terminal)],
      conditions: context.conditions,
    };
    const key = JSON.stringify(path);
    if (seen.has(key)) return;
    seen.add(key);
    paths.push(path);
  };
  const functionBody = (
    fn: SymbolicFunction,
    args: readonly SymbolicValue[],
    context: PathContext,
    invocationNode: t.Node,
  ): void => {
    if (context.active.has(fn.node)) return;
    if (fn.conditionUnresolved === true) {
      accumulator.unknownFindings += 1;
      return;
    }
    const name =
      (t.isFunctionExpression(fn.node) || t.isFunctionDeclaration(fn.node)) &&
      fn.node.id
        ? fn.node.id.name
        : "closure";
    walk(fn.node.body, resolver.bind(fn, args, invocationNode), {
      ...context,
      steps: [
        ...context.steps,
        ...fn.origins.map((n) =>
          step(
            n,
            "factory",
            t.isCallExpression(n) ? callLabel(n.callee) : "factory",
          ),
        ),
        step(fn.node, "function", name),
      ],
      active: new Set([...context.active, fn.node]),
    });
  };
  const ipc = (
    node: t.CallExpression | t.OptionalCallExpression,
    descriptor: ElectronIpcDescriptor,
    args: readonly SymbolicValue[],
    context: PathContext,
    endpoint: string,
    identity: ElectronApiIdentity,
  ): void => {
    const first = args[0];
    if (first?.kind !== "literal" || typeof first.value !== "string") {
      accumulator.unknownFindings += 1;
      return;
    }
    const channelContext = metadataContext(context, first);
    if (!channelContext) return;
    const handlerValue = args[1] ?? symbolicUnknown("missing handler");
    const handlerContext = metadataContext(channelContext, handlerValue);
    if (!handlerContext) return;
    const channel = first.value;
    const linkedPath = sourcePathOf(node);
    const location = range(linkedPath === null ? node : context.local);
    const invocationLocation =
      JSON.stringify(range(context.entryNode)) === JSON.stringify(location)
        ? undefined
        : range(context.entryNode);
    // The substitution itself is recorded as the wrapper resolution basis.
    const findingContext = {
      electron_identity: identity,
      module_key: null,
      location,
      ...(invocationLocation === undefined
        ? {}
        : { invocation_location: invocationLocation }),
      ...(linkedPath === null
        ? {}
        : {
            linked_operation: {
              source_path: linkedPath,
              location: range(node),
            },
          }),
    };
    const handlers = symbolicVariants(handlerValue);
    // A channel registration must not acquire one arbitrary handler from a union.
    // Keep the unresolved registration so it still competes with other handlers.
    const fn =
      handlers.length === 1 && handlers[0]?.kind === "function"
        ? handlers[0]
        : undefined;
    const handlerNode = node.arguments[1];
    const finding: ElectronIpcFinding =
      descriptor.mode === "send" || descriptor.mode === "invoke"
        ? {
            ...descriptor,
            channel,
            channel_expression: null,
            handler_kind: null,
            handler_location: null,
            ...findingContext,
          }
        : fn && sourcePathOf(fn.node) === null
          ? {
              ...descriptor,
              channel,
              channel_expression: null,
              handler_kind: "inline-function",
              handler_location: range(fn.node),
              ...findingContext,
            }
          : fn
            ? {
                ...descriptor,
                channel,
                channel_expression: null,
                handler_kind: "dynamic-expression",
                handler_location: location,
                ...findingContext,
              }
            : handlerNode
              ? {
                  ...descriptor,
                  channel,
                  channel_expression: null,
                  handler_kind: "dynamic-expression",
                  handler_location:
                    linkedPath === null ? range(handlerNode) : location,
                  ...findingContext,
                }
              : {
                  ...descriptor,
                  channel,
                  channel_expression: null,
                  handler_kind: "missing",
                  handler_location: null,
                  ...findingContext,
                };
    // A transmission is one source fact for every path that reaches it;
    // registrations keep their invocation because handlers compete.
    const key = JSON.stringify([
      finding.side,
      finding.operation,
      channel,
      location,
      descriptor.mode === "send" || descriptor.mode === "invoke"
        ? null
        : (invocationLocation ?? null),
      finding.handler_kind,
      finding.handler_location,
    ]);
    const known = pendingIpc.get(key);
    const pending = known ?? {
      offset: (linkedPath === null ? node : context.local).start ?? -1,
      finding,
      alternatives: [],
    };
    pending.alternatives.push(channelContext.guards);
    pendingIpc.set(key, pending);
    if (descriptor.mode === "send" || descriptor.mode === "invoke") {
      emit(channelContext, node, endpoint, channel);
      return;
    }
    // Handler bodies are traced after every reachable registration is
    // recorded, so their expansion cannot consume the registrations' budget.
    if (descriptor.side === "main" && fn && known === undefined)
      handlerBodies.push(() => {
        // A registration reached on every branch traces its handler without
        // the branch predicates that merged away.
        const registration = channelContext.guards.length;
        const merged = mergeGuardAlternatives(pending.alternatives).some(
          (guards) => guards.length === 0,
        );
        const guards = merged
          ? handlerContext.guards.slice(registration)
          : handlerContext.guards;
        functionBody(
          fn,
          [
            { kind: "external", path: ["ipc-event"] },
            symbolicUnknown("IPC payload"),
          ],
          {
            ...handlerContext,
            guards,
            conditions: guards.map(({ condition }) => condition),
            entryKind: "ipc-handler",
            entry: channel,
            channel,
            steps: [...context.steps, step(node, "ipc", endpoint)],
          },
          node,
        );
      });
  };
  const bridge = (
    node: t.CallExpression | t.OptionalCallExpression,
    exposure: JavaScriptContextBridgeExposureArguments<SymbolicValue>,
    context: PathContext,
    guardedDispatch: boolean,
    identity: ElectronApiIdentity,
  ): void => {
    const key = exposure.apiKey;
    const object = exposure.api;
    const worldValue =
      exposure.worldId === null
        ? null
        : (exposure.worldId ?? symbolicUnknown("missing world id"));
    const worldContext =
      worldValue === null ? context : metadataContext(context, worldValue);
    if (!worldContext) return;
    const worldId =
      worldValue === null
        ? null
        : electronStaticSymbolicValue(
            worldValue,
            exposure.worldIdIndex === null
              ? undefined
              : argumentNode(node.arguments[exposure.worldIdIndex]),
          );
    if (worldId?.status === "dynamic") accumulator.unknownFindings += 1;
    if (key?.kind !== "literal" || typeof key.value !== "string" || !object) {
      accumulator.unknownFindings += 1;
      return;
    }
    const keyContext = metadataContext(worldContext, key);
    if (!keyContext || !metadataContext(keyContext, object)) return;
    const members = [...resolver.members(object)].sort();
    const location = range(node);
    const existing = accumulator.contextBridgeApis.find(
      ({ value }) =>
        JSON.stringify(value.location) === JSON.stringify(location),
    );
    const finding: ElectronContextBridgeFinding = {
      world: exposure.world,
      world_id: worldId,
      api_key: key.value,
      api_key_expression: null,
      api_status: "dynamic" as const,
      resolution_basis: "wrapper-substitution" as const,
      members,
      conditional_members: [],
      unknown_members: resolver.unknownMembers(object),
      electron_identity: identity,
      module_key: null,
      location,
    };
    // This report shape has no predicate field, so a guarded world or object
    // cannot be recorded as an unconditional exposure fact.
    const guardedWorld = worldValue !== null && hasConditions(worldValue);
    const guardedKey = hasConditions(key);
    const guardedObject = hasConditions(object);
    const guarded =
      context.conditions.length > 0 ||
      guardedWorld ||
      guardedKey ||
      guardedObject ||
      guardedDispatch;
    if (guarded) accumulator.unknownFindings += 1;
    // Existing entries are raw syntax observations and remain valid even when
    // symbolic substitution can only describe this call under a predicate.
    // A bound object keeps its nested member paths, conditional members and
    // member-write uncertainty, which substitution does not report.
    if (!guarded && existing)
      existing.value.api_status !== "object-binding" &&
        (existing.value.api_status !== "object-literal" ||
          existing.value.unknown_members > 0) &&
        accumulator.contextBridgeApis.splice(
          accumulator.contextBridgeApis.indexOf(existing),
          1,
          { offset: node.start ?? -1, value: finding },
        );
    else if (!guarded)
      accumulator.contextBridgeApis.push({
        offset: node.start ?? -1,
        value: finding,
      });
    // Exposed functions are traced at every exact member path of the API
    // object; contextBridge copies nested plain objects member by member.
    const exposeMembers = (
      value: SymbolicValue,
      path: string,
      depth: number,
      context: PathContext,
    ): void => {
      for (const variant of symbolicVariants(value)) {
        const memberContext = metadataContext(context, variant);
        if (!memberContext) continue;
        if (variant.kind === "function")
          functionBody(
            variant,
            variant.node.params.map(() =>
              symbolicUnknown("public API argument"),
            ),
            {
              ...memberContext,
              entryNode: node,
              entryKind: "bridge-member",
              entry: path,
              channel: null,
              steps: [step(node, "exposure", path)],
              active: new Set(),
            },
            node,
          );
        else if (
          depth < MAX_EXPOSED_MEMBER_DEPTH &&
          (variant.kind === "object" || variant.kind === "record")
        )
          for (const name of resolver.members(variant))
            exposeMembers(
              resolver.property(variant, name),
              `${path}.${name}`,
              depth + 1,
              memberContext,
            );
      }
    };
    for (const name of members)
      exposeMembers(
        resolver.property(object, name),
        `${key.value}.${name}`,
        1,
        keyContext,
      );
  };

  const call = (
    node: t.CallExpression | t.OptionalCallExpression,
    env: SymbolicEnvironment,
    outer: PathContext,
    evaluatedCallee?: SymbolicValue,
  ): void => {
    const context =
      sourcePathOf(node) === null ? { ...outer, local: node } : outer;
    const value = evaluatedCallee ?? resolver.evaluate(node.callee, env);
    // Read arguments only for callees that consume them; see the resolver.
    let args: readonly SymbolicValue[] | undefined;
    const callArguments = () => (args ??= resolver.arguments(node, env));
    const target = node.callee;
    // A fulfillment callback runs once its promise is fulfilled.
    if (
      (t.isMemberExpression(target) || t.isOptionalMemberExpression(target)) &&
      semanticStaticPropertyKey(target.property, target.computed) === "then"
    )
      for (const promise of symbolicVariants(
        resolver.evaluate(target.object, env),
      )) {
        if (promise.kind !== "promise") continue;
        const fn = callArguments()[0];
        if (fn?.kind !== "function") continue;
        const settled = metadataContext(context, promise);
        const fulfilled =
          settled === null || promise.fulfilled
            ? settled
            : condition(settled, promise.node, "fulfilled", env);
        if (fulfilled !== null)
          functionBody(
            fn,
            [symbolicUnknown("fulfillment value")],
            {
              ...fulfilled,
              steps: [
                ...fulfilled.steps,
                step(node, "call", callLabel(target)),
              ],
            },
            node,
          );
      }
    for (const callee of symbolicVariants(value)) {
      const branchContext = metadataContext(context, callee);
      if (!branchContext) continue;
      if (callee.kind === "function") {
        functionBody(
          callee,
          callArguments(),
          {
            ...branchContext,
            steps: [
              ...branchContext.steps,
              step(node, "call", callLabel(node.callee)),
            ],
          },
          node,
        );
      } else if (callee.kind === "external") {
        const path = callee.path;
        const endpoint = path.join(".");
        const calleeIdentity = callee.identity ?? { basis: "module-binding" };
        if (identity.intactExport(path)) {
          const descriptor = ipcDescriptor(path.slice(1));
          const exposure =
            path.length === 3 && path[1] === "contextBridge"
              ? contextBridgeExposureArguments(path[2] ?? "", callArguments())
              : undefined;
          if (exposure)
            bridge(
              node,
              exposure,
              branchContext,
              hasConditions(callee),
              calleeIdentity,
            );
          else if (descriptor)
            ipc(
              node,
              descriptor,
              callArguments(),
              branchContext,
              endpoint,
              calleeIdentity,
            );
          else if (path[1] === "clipboard") emit(branchContext, node, endpoint);
        } else if (
          (path[0] === "navigator" && path[1] === "clipboard") ||
          (path[0] === "ipc-event" && path[1] === "sender")
        )
          emit(branchContext, node, endpoint);
      }
    }
  };
  function walk(
    node: t.Node,
    env: SymbolicEnvironment,
    context: PathContext,
  ): void {
    if (--remainingVisits < visitFloor || t.isFunction(node) || t.isClass(node))
      return;
    if (t.isBlockStatement(node)) {
      let next = context;
      for (const statement of node.body) {
        walk(statement, env, next);
        if (symbolicDefiniteExit(statement)) break;
        if (t.isIfStatement(statement)) {
          const truth = symbolicTruth(resolver.evaluate(statement.test, env));
          if (truth !== undefined) {
            if (
              symbolicDefiniteExit(
                truth ? statement.consequent : statement.alternate,
              )
            )
              break;
          } else if (symbolicDefiniteExit(statement.consequent))
            next = condition(next, statement.test, false, env);
          else if (symbolicDefiniteExit(statement.alternate))
            next = condition(next, statement.test, true, env);
        }
      }
      return;
    }
    if (t.isIfStatement(node) || t.isConditionalExpression(node)) {
      const truth = symbolicTruth(resolver.evaluate(node.test, env));
      if (truth !== false)
        walk(
          node.consequent,
          env,
          truth === undefined
            ? condition(context, node.test, true, env)
            : context,
        );
      if (truth !== true && node.alternate)
        walk(
          node.alternate,
          env,
          truth === undefined
            ? condition(context, node.test, false, env)
            : context,
        );
      return;
    }
    if (t.isLogicalExpression(node)) {
      walk(node.left, env, context);
      const right = symbolicLogicalRight(
        node.operator,
        resolver.evaluate(node.left, env),
      );
      if (right === false) return;
      walk(
        node.right,
        env,
        right === undefined
          ? condition(
              context,
              node.left,
              node.operator === "??" ? "nullish" : node.operator === "&&",
              env,
            )
          : context,
      );
      return;
    }
    if (t.isForOfStatement(node) && !node.await) {
      walk(node.right, env, context);
      if (symbolicLoopHasExit(node)) {
        accumulator.unknownFindings += 1;
        return;
      }
      const iterable = resolver.evaluate(node.right, env);
      // Each element of an exact array is substituted into the loop body.
      const iterations =
        iterable.kind === "array" &&
        iterable.conditions === undefined &&
        !iterable.conditionUnresolved
          ? iterable.values.map((element) =>
              resolver.bindIteration(node, element, env),
            )
          : [undefined];
      for (const iteration of iterations.includes(undefined)
        ? [env]
        : iterations)
        walk(node.body, iteration ?? env, context);
      return;
    }
    if (t.isCallExpression(node) || t.isOptionalCallExpression(node))
      call(node, env, context);
    for (const child of childNodes(node)) walk(child, env, context);
  }
  const wrapperEntries = new Set<t.Node>(identity.wrapperEntries.calls);
  if (!identity.wrapperEntries.complete) {
    accumulator.unknownFindings += 1;
    accumulator.electronCallPathLimitReached = true;
  }
  traverseJavaScriptAst(program, {
    enter: (node) => {
      if (!t.isCallExpression(node) && !t.isOptionalCallExpression(node))
        return;
      const isolatedSeed = t.isStringLiteral(node.arguments[0])
        ? undefined
        : isolatedBridgeCall(node);
      if (
        !t.isStringLiteral(node.arguments[0]) &&
        isolatedSeed === undefined &&
        !wrapperEntries.has(node)
      )
        return;
      const env = isolatedSeed?.env ?? resolver.environmentAt(node);
      let context: PathContext = {
        entryNode: node,
        entry: "",
        entryKind: null,
        channel: null,
        steps: [],
        conditions: [],
        guards: [],
        local: node,
        active: new Set(),
      };
      for (
        let child: t.Node = node, parent = state.parentsByNode.get(child);
        parent && !t.isFunction(parent);
        child = parent, parent = state.parentsByNode.get(child)
      ) {
        if (
          t.isForOfStatement(parent) &&
          child !== parent.right &&
          (parent.await || symbolicLoopHasExit(parent))
        ) {
          accumulator.unknownFindings += 1;
          return;
        } else if (
          t.isIfStatement(parent) ||
          t.isConditionalExpression(parent)
        ) {
          if (child === parent.test) continue;
          const truth = symbolicTruth(resolver.evaluate(parent.test, env));
          const positive = child === parent.consequent;
          if (truth !== undefined && truth !== positive) return;
          if (truth === undefined)
            context = condition(context, parent.test, positive, env);
        } else if (t.isLogicalExpression(parent) && child === parent.right) {
          const right = symbolicLogicalRight(
            parent.operator,
            resolver.evaluate(parent.left, env),
          );
          if (right === false) return;
          if (right === undefined)
            context = condition(
              context,
              parent.left,
              parent.operator === "??" ? "nullish" : parent.operator === "&&",
              env,
            );
        } else if (t.isBlockStatement(parent)) {
          const index = parent.body.findIndex(
            (statement) => statement === child,
          );
          if (
            index >= 0 &&
            parent.body
              .slice(0, index)
              .some((statement) => symbolicDefiniteExit(statement))
          )
            return;
        }
      }
      call(node, env, context, isolatedSeed?.callee);
    },
  });
  // Each handler body receives an equal share of the remaining visits, so
  // one expansive handler cannot hide the paths of the handlers after it.
  for (
    let index = 0;
    index < handlerBodies.length && remainingVisits >= 0;
    index += 1
  ) {
    const share = Math.floor(remainingVisits / (handlerBodies.length - index));
    visitFloor = remainingVisits - share;
    const body = handlerBodies[index]!;
    const exhausted = resolver.share(handlerBodies.length - index, () =>
      resolver.dispatch(body),
    );
    if (exhausted) handlerBudgetReached = true;
    if (remainingVisits < visitFloor) handlerBudgetReached = true;
    remainingVisits = Math.max(remainingVisits, visitFloor);
    visitFloor = 0;
  }
  // A guarded registration also reached unconditionally from an outer
  // invocation is the same registration seen with less context.
  const resolved = [...pendingIpc.values()].map((pending) => ({
    pending,
    alternatives: mergeGuardAlternatives(pending.alternatives),
  }));
  const operationKey = ({ finding }: PendingIpcFinding): string =>
    JSON.stringify([
      finding.side,
      finding.operation,
      finding.channel,
      finding.location,
      finding.handler_location,
    ]);
  const unconditional = new Set(
    resolved.flatMap(({ pending, alternatives }) =>
      alternatives.some((guards) => guards.length === 0)
        ? [operationKey(pending)]
        : [],
    ),
  );
  for (const { pending, alternatives } of resolved)
    if (
      alternatives.some((guards) => guards.length === 0) ||
      !unconditional.has(operationKey(pending))
    )
      addIpcFinding(accumulator, pending.finding, pending.offset, alternatives);
    else accumulator.unknownFindings += 1;
  if (remainingVisits < 0 || handlerBudgetReached || resolver.truncated) {
    accumulator.unknownFindings += 1;
    accumulator.electronCallPathLimitReached = true;
  }
  if (resolver.unresolved) accumulator.unknownFindings += 1;
  return paths;
};

/**
 * Record one substituted IPC operation. Guard conjunctions that differ only
 * in the polarity of one predicate of the same activation are merged; an
 * operation reached under an empty conjunction is unconditional. Otherwise
 * the remaining conjunctions are retained and the operation is not a
 * pairing candidate.
 */
const addIpcFinding = (
  accumulator: JavaScriptAnalysisAccumulator,
  finding: ElectronIpcFinding,
  offset: number,
  alternatives: readonly (readonly PathGuard[])[],
): void => {
  const unconditional = alternatives.some((guards) => guards.length === 0);
  // A fully observed transmission stays one source fact when its callback is
  // traced. Registrations retain invocation identity because handlers compete.
  const duplicate = accumulator.ipc.some(
    ({ value }) =>
      value.side === finding.side &&
      value.operation === finding.operation &&
      value.channel === finding.channel &&
      JSON.stringify(value.location) === JSON.stringify(finding.location) &&
      ((value.resolution_basis === undefined &&
        (value.mode === "send" || value.mode === "invoke")) ||
        JSON.stringify(value.invocation_location) ===
          JSON.stringify(finding.invocation_location)),
  );
  if (!unconditional) accumulator.unknownFindings += 1;
  if (duplicate) return;
  if (
    unconditional &&
    finding.mode !== "send" &&
    finding.mode !== "invoke" &&
    finding.handler_kind !== "inline-function"
  )
    accumulator.unknownFindings += 1;
  const conjunctions = new Map(
    alternatives.map((guards) => {
      const conditions = guards.map(({ condition }) => condition);
      return [JSON.stringify(conditions), conditions];
    }),
  );
  accumulator.ipc.push({
    offset,
    value: {
      ...finding,
      resolution_basis: "wrapper-substitution",
      ...(unconditional
        ? {}
        : { guard_alternatives: [...conjunctions.values()] }),
    },
  });
};

const complementary = (left: GuardPolarity, right: GuardPolarity): boolean =>
  typeof left === "boolean"
    ? typeof right === "boolean" && left !== right
    : (left === "nullish" && right === "not-nullish") ||
      (left === "not-nullish" && right === "nullish");

/**
 * Reduce guard conjunctions: drop repeated guards and conjunctions implied by
 * a shorter one, and resolve two conjunctions that differ only by one
 * complementary guard of the same node and activation.
 */
const mergeGuardAlternatives = (
  alternatives: readonly (readonly PathGuard[])[],
): readonly (readonly PathGuard[])[] => {
  const same = (left: PathGuard, right: PathGuard): boolean =>
    left.node === right.node &&
    left.environment === right.environment &&
    left.positive === right.positive;
  let current = alternatives.map((guards) =>
    guards.filter(
      (guard, index) =>
        guards.findIndex((other) => same(guard, other)) === index,
    ),
  );
  for (let changed = true; changed;) {
    changed = false;
    current = current.filter(
      (guards, index) =>
        !current.some(
          (other, otherIndex) =>
            otherIndex !== index &&
            other.every((guard) => guards.some((g) => same(g, guard))) &&
            (other.length < guards.length || otherIndex < index),
        ),
    );
    search: for (const [index, left] of current.entries())
      for (const right of current.slice(index + 1)) {
        if (left.length !== right.length) continue;
        const missing = left.filter(
          (guard) => !right.some((g) => same(g, guard)),
        );
        const extra = right.filter(
          (guard) => !left.some((g) => same(g, guard)),
        );
        const [a] = missing;
        const [b] = extra;
        if (
          missing.length !== 1 ||
          extra.length !== 1 ||
          a === undefined ||
          b === undefined ||
          a.node !== b.node ||
          a.environment === null ||
          a.environment !== b.environment ||
          !complementary(a.positive, b.positive)
        )
          continue;
        current = [
          ...current.filter((guards) => guards !== left && guards !== right),
          left.filter((guard) => guard !== a),
        ];
        changed = true;
        break search;
      }
  }
  return current;
};
