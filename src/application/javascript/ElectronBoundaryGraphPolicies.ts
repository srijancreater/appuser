import type { ApplicationNode } from "../../domain/javascript/javascriptApplicationGraphSchemas.js";
import type { ElectronContentSecurityPolicyFinding } from "../../domain/javascript/electronStaticAnalysisTypes.js";
import type { JavaScriptArtifactFile } from "../../domain/javascript/javascriptArtifactFiles.js";
import { completeApplicationCoverage } from "../../domain/javascript/javascriptApplicationEvidenceSchemas.js";
import {
  javascriptAnalysisCoverage,
  type JavaScriptArtifactGraphContext,
  type JavaScriptArtifactGraphCoverage,
} from "./JavaScriptArtifactGraphContext.js";
import { astObservationEvidence } from "./JavaScriptArtifactGraphEvidence.js";
import { electronFindingSourceNode } from "./ElectronBoundaryGraphContext.js";

/** Attach Content-Security-Policy facts to the JavaScript or HTML that declares them. */
export const addElectronPolicyBoundaries = (
  context: JavaScriptArtifactGraphContext,
): void => {
  for (const { file, javascript } of context.analysis.files) {
    if (javascript === null) continue;
    const coverage = javascriptAnalysisCoverage(javascript);
    for (const policy of javascript.electron.content_security_policies) {
      const target = electronFindingSourceNode(
        context,
        file,
        policy.module_key,
        policy.module_runtime,
      );
      if (target !== undefined)
        addPolicy(context, { file, target, policy, coverage });
    }
  }
  for (const { html_path: path, policy } of context.analysis.html_policies) {
    const file = context.filesByPath.get(path);
    const target = context.assetNodes.get(path) ?? context.fileNodes.get(path);
    if (file !== undefined && target !== undefined)
      addPolicy(context, {
        file,
        target,
        policy,
        coverage: completeApplicationCoverage(),
      });
  }
};

const addPolicy = (
  context: JavaScriptArtifactGraphContext,
  input: {
    readonly file: JavaScriptArtifactFile;
    readonly target: ApplicationNode;
    readonly policy: ElectronContentSecurityPolicyFinding;
    readonly coverage: JavaScriptArtifactGraphCoverage;
  },
): void => {
  const { file, target, policy, coverage } = input;
  context.accumulator.addNode({
    kind: target.kind,
    identity: target.identity,
    observations: [
      {
        label: policy.header ?? "content-security-policy",
        properties: {
          fact_kind: "content-security-policy",
          mechanism: policy.mechanism,
          header: policy.header,
          policy: policy.policy,
          policy_expression: policy.policy_expression,
          directives: policy.directives,
          concerns: policy.concerns,
          dynamic_parts: policy.dynamic_parts,
        },
        evidence: astObservationEvidence({
          sha256: file.sha256,
          path: file.path,
          range: policy.location,
          operation: "observe-content-security-policy",
          coverage,
          limitations: [
            "The policy text is observed where it is declared; static syntax does not prove which responses or documents it is applied to.",
            ...(policy.dynamic_parts === 0
              ? []
              : [
                  "Parts of the policy are computed at runtime and appear as ${…}; directives containing them were not judged.",
                ]),
          ],
        }),
      },
    ],
  });
};
