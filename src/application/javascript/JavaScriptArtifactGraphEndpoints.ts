import { compactStringIdentityKey } from "../../domain/compactStringIdentity.js";
import type { JavaScriptStaticAnalysis } from "../../domain/javascript/javascriptStaticAnalysisTypes.js";
import { classifyJavaScriptUrlValue } from "../../domain/javascript/javascriptUrlValues.js";
import {
  addAstContainsEdge,
  addStaticInferenceEdge,
  artifactLocalIdentity,
  sourceNodeFor,
  type JavaScriptArtifactGraphContext,
} from "./JavaScriptArtifactGraphContext.js";
import { astObservationEvidence } from "./JavaScriptArtifactGraphEvidence.js";
import type { FindingInput } from "./JavaScriptArtifactGraphFindings.js";

type StaticEndpoint = JavaScriptStaticAnalysis["endpoints"][number];

const DATA_VALUE_LIMITATION =
  "The value is present in string data; no recognized network call or route consumes it at this location.";

const HOST_CLASS_LIMITATION =
  "Host-only classification is inferred from DNS name syntax and top-level domain; dotted identifiers can share that syntax.";

const DERIVED_VALUE_LIMITATION =
  "The value was folded from a constant expression without executing it; the expression property retains its source.";

/**
 * Project one endpoint value. Call-site and route endpoints are inferred
 * relationships; data values are exact containment in their source module.
 */
export const addJavaScriptEndpoint = (
  context: JavaScriptArtifactGraphContext,
  input: FindingInput<StaticEndpoint>,
): void => {
  const source =
    sourceNodeFor(
      context,
      input.file.path,
      input.value.module_key,
      input.value.module_runtime,
    ) ?? input.asset;
  const key = compactStringIdentityKey(input.value.value);
  const label = `${input.value.kind} endpoint`;
  const classification = classifyJavaScriptUrlValue(input.value.value);
  const node = context.accumulator.addNode({
    kind: "endpoint",
    identity: artifactLocalIdentity(input.file.sha256, input.value.kind, key),
    observations: [
      {
        label:
          input.value.value.length <= label.length ? input.value.value : label,
        properties: {
          endpoint_kind: input.value.kind,
          value: input.value.value,
          expression: input.value.expression,
          mechanism: input.value.mechanism,
          url_class: classification?.url_class ?? null,
          host: classification?.host ?? null,
          property_path: input.value.property_path,
        },
        evidence: astObservationEvidence({
          sha256: input.file.sha256,
          path: input.file.path,
          range: input.value.location,
          operation: "discover-static-endpoint",
          coverage: input.coverage,
          limitations: [
            ...(input.value.expression === null
              ? []
              : [DERIVED_VALUE_LIMITATION]),
            ...(input.value.kind === "data" ? [DATA_VALUE_LIMITATION] : []),
            ...(classification?.url_class === "host"
              ? [HOST_CLASS_LIMITATION]
              : []),
          ],
        }),
      },
    ],
  });
  const edge = {
    source,
    target: node,
    file: input.file,
    range: input.value.location,
    coverage: input.coverage,
    properties: { mechanism: input.value.mechanism },
  };
  if (input.value.kind === "data")
    addAstContainsEdge(context, {
      ...edge,
      operation: "locate-data-endpoint-value",
    });
  else
    addStaticInferenceEdge(context, {
      ...edge,
      relation: input.value.kind === "route" ? "exposes" : "calls",
    });
};
