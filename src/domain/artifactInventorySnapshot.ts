import type {
  ArtifactInventoryCoverage,
  ArtifactInventoryResult,
  ArtifactNode,
  IntegrityContradiction,
} from "./artifactGraph.js";

/** Immutable inventory produced by one complete artifact scan. */
export interface ArtifactInventorySnapshot {
  readonly coverage_status: ArtifactInventoryCoverage;
  readonly manifest: ArtifactInventoryResult["manifest"];
  /** Canonical code-point order by artifact_id, shared by scan and Evidence reconstruction. */
  readonly nodes: readonly ArtifactNode[];
  /** Canonical code-point order by logical_path. */
  readonly occurrences: ArtifactInventoryResult["occurrences"];
  readonly edges: ArtifactInventoryResult["edges"];
  readonly provenance: ReadonlyArray<
    ArtifactInventoryResult["provenance"][number]
  >;
  readonly integrity_contradictions: readonly IntegrityContradiction[];
  readonly limitations: readonly string[];
}
