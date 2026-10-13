import type { ElectronNativeAddonBindingFinding } from "../../domain/javascript/electronStaticAnalysisTypes.js";
import type { JavaScriptArtifactFile } from "../../domain/javascript/javascriptArtifactFiles.js";
import {
  javascriptAnalysisCoverage,
  type JavaScriptArtifactGraphContext,
  type JavaScriptArtifactGraphCoverage,
} from "./JavaScriptArtifactGraphContext.js";
import { astObservationEvidence } from "./JavaScriptArtifactGraphEvidence.js";
import { resolveElectronNativeAddon } from "./ElectronBoundaryAnalysis.js";
import { compositeKey } from "../../domain/unicodeCodePointOrder.js";
import { javascriptDisplayText } from "../../domain/javascript/javascriptAstValues.js";
import {
  addElectronInferenceEdge,
  electronFindingSourceNode,
  electronObservationIdentity,
  electronRangeKey,
} from "./ElectronBoundaryGraphContext.js";

interface NativeBindingInput {
  readonly context: JavaScriptArtifactGraphContext;
  readonly file: JavaScriptArtifactFile;
  readonly value: ElectronNativeAddonBindingFinding;
  readonly coverage: JavaScriptArtifactGraphCoverage;
}

/** Project JavaScript-requested native addon binding and re-export surfaces. */
export const addElectronNativeBoundaries = (
  context: JavaScriptArtifactGraphContext,
): void => {
  for (const analyzed of context.analysis.files) {
    const { file, javascript } = analyzed;
    if (javascript === null) continue;
    const coverage = javascriptAnalysisCoverage(javascript);
    for (const value of javascript.electron.native_addon_bindings)
      addNativeBinding({ context, file, value, coverage });
  }
};

const addNativeBinding = (input: NativeBindingInput): void => {
  const { context, file, value, coverage } = input;
  const source = electronFindingSourceNode(
    context,
    file,
    value.module_key,
    value.module_runtime,
  );
  if (source === undefined) return;
  const resolution = resolveElectronNativeAddon(
    file,
    value,
    context.filesByPath,
  );
  const resolved = resolution.resolved_path;
  const addon = resolved === null ? undefined : context.fileNodes.get(resolved);
  const binding = context.accumulator.addNode({
    kind: "native-export",
    identity: electronObservationIdentity(
      context,
      "javascript-requested-native-export",
      compositeKey([
        file.path,
        value.specifier,
        value.binding_kind,
        value.members,
        value.namespace_access ?? null,
        value.dynamic_member_access ?? null,
        electronRangeKey(value.location),
      ]),
    ),
    observations: [
      {
        label:
          value.members.map(javascriptDisplayText).join(", ") ||
          value.specifier,
        properties: {
          specifier: value.specifier,
          specifier_status: value.specifier_status,
          binding_kind: value.binding_kind,
          loader: value.loader,
          loader_basis: value.loader_basis,
          requested_members: value.members,
          namespace_access: value.namespace_access ?? null,
          dynamic_member_access: value.dynamic_member_access ?? null,
          resolved_path: resolved,
          resolution_basis: resolution.basis,
          candidate_paths: resolution.candidates,
          native_export_verification: "not-performed",
        },
        evidence: astObservationEvidence({
          sha256: file.sha256,
          path: file.path,
          range: value.location,
          operation: "observe-native-addon-binding",
          coverage,
          limitations: [
            "JavaScript syntax identifies requested member names; it does not prove that the native binary exports or implements them.",
            ...(resolution.basis === "create-require-base-unavailable"
              ? [
                  "createRequire's base filename was not retained, so the requested add-on path remains unresolved; the calling source directory is not substituted.",
                ]
              : []),
          ],
        }),
      },
    ],
  });
  addElectronInferenceEdge(context, {
    source,
    target: binding,
    file,
    range: value.location,
    coverage,
    relation: value.binding_kind === "re-export" ? "exposes" : "imports",
    operation: "map-native-addon-binding",
    properties: {
      specifier: value.specifier,
      binding_kind: value.binding_kind,
      requested_members: value.members,
      namespace_access: value.namespace_access ?? null,
      dynamic_member_access: value.dynamic_member_access ?? null,
    },
    limitations: [
      "Requested JavaScript members are not verified native exports.",
    ],
  });
  if (addon === undefined || resolved === null) return;
  addElectronInferenceEdge(context, {
    source: addon,
    target: binding,
    file,
    range: value.location,
    coverage,
    relation: "exposes",
    operation: "associate-native-addon-requested-exports",
    properties: {
      resolved_path: resolved,
      resolution_basis: resolution.basis,
      requested_members: value.members,
      namespace_access: value.namespace_access ?? null,
      dynamic_member_access: value.dynamic_member_access ?? null,
      verified: false,
    },
    confidence: resolution.basis === "specifier" ? "medium" : "low",
    limitations: [
      "The .node artifact path is resolved, but requested JavaScript members have not been verified against native symbols.",
      ...(resolution.basis === "specifier"
        ? []
        : [
            "The loader selects its add-on at runtime; this is the only build or prebuild add-on under the nearest package root.",
          ]),
    ],
  });
};
