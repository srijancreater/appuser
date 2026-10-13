/** One directive of a Content Security Policy, in source order. */
export interface ContentSecurityPolicyDirective {
  readonly name: string;
  readonly sources: readonly string[];
}

/** A directive source or omission that allows a broad set of content. */
export interface ContentSecurityPolicyConcern {
  readonly directive: string;
  readonly source: string | null;
  readonly reason: string;
}

/** Parsed policy; sources containing DYNAMIC_SOURCE are not judged. */
export interface ParsedContentSecurityPolicy {
  readonly directives: readonly ContentSecurityPolicyDirective[];
  readonly concerns: readonly ContentSecurityPolicyConcern[];
}

/** Placeholder for a value computed at runtime inside a policy string. */
export const DYNAMIC_SOURCE = "${…}";

const DIRECTIVES = new Set([
  "default-src",
  "script-src",
  "script-src-elem",
  "script-src-attr",
  "style-src",
  "style-src-elem",
  "style-src-attr",
  "img-src",
  "connect-src",
  "font-src",
  "media-src",
  "object-src",
  "frame-src",
  "child-src",
  "worker-src",
  "manifest-src",
  "prefetch-src",
  "fenced-frame-src",
  "base-uri",
  "form-action",
  "frame-ancestors",
  "navigate-to",
  "sandbox",
  "plugin-types",
  "report-uri",
  "report-to",
  "require-trusted-types-for",
  "trusted-types",
  "upgrade-insecure-requests",
  "block-all-mixed-content",
]);
const SCRIPT_DIRECTIVES = new Set([
  "default-src",
  "script-src",
  "script-src-elem",
  "script-src-attr",
]);
const STYLE_DIRECTIVES = new Set([
  "style-src",
  "style-src-elem",
  "style-src-attr",
]);
const SOURCE_LIST =
  /-src(?:-elem|-attr)?$|^(?:base-uri|form-action|frame-ancestors)$/u;
const NETWORK_SCHEMES = new Set([
  "http:",
  "https:",
  "ws:",
  "wss:",
  "file:",
  "filesystem:",
]);
const SCRIPT_SCHEMES = new Set(["data:", "blob:"]);

/**
 * Parse a serialized policy (CSP Level 3 `;`-separated directives). Returns
 * undefined unless at least one directive name is known. Declared policies retain
 * unknown directives; arbitrary text must use only known directives. With
 * `requireMultiple`, a single directive is not enough evidence that arbitrary
 * text is a policy.
 */
export const parseContentSecurityPolicy = (
  text: string,
  requireMultiple: boolean,
): ParsedContentSecurityPolicy | undefined => {
  const directives: ContentSecurityPolicyDirective[] = [];
  for (const part of text.split(";")) {
    const tokens = part
      .trim()
      .split(/[\t\n\f\r ]+/u)
      .filter(Boolean);
    const [rawName, ...sources] = tokens;
    if (rawName === undefined) continue;
    const name = rawName.toLowerCase();
    if (!DIRECTIVES.has(name) && requireMultiple) return undefined;
    directives.push({ name, sources });
  }
  if (
    !directives.some(({ name }) => DIRECTIVES.has(name)) ||
    (requireMultiple && directives.length < 2)
  )
    return undefined;
  return { directives, concerns: concerns(directives) };
};

const concerns = (
  directives: readonly ContentSecurityPolicyDirective[],
): readonly ContentSecurityPolicyConcern[] => {
  const found: ContentSecurityPolicyConcern[] = [];
  const first = new Map<string, ContentSecurityPolicyDirective>();
  for (const directive of directives)
    if (!first.has(directive.name)) first.set(directive.name, directive);
  const effective = [...first.values()];
  const names = new Set(effective.map(({ name }) => name));
  const dynamic = effective.some(({ sources }) =>
    sources.some((source) => source.includes(DYNAMIC_SOURCE)),
  );
  for (const { name, sources } of effective) {
    if (
      !SOURCE_LIST.test(name) ||
      sources.some((source) => source.includes(DYNAMIC_SOURCE))
    )
      continue;
    const lowered = sources.map((source) => source.toLowerCase());
    const nonceOrHash = lowered.some((source) =>
      /^'(?:nonce|sha256|sha384|sha512)-/u.test(source),
    );
    for (const source of lowered) {
      const reason = sourceConcern(name, source, nonceOrHash);
      if (reason !== undefined) found.push({ directive: name, source, reason });
    }
  }
  // Omissions are judged only when every directive value is static.
  if (!dynamic && !names.has("default-src")) {
    if (!names.has("script-src")) {
      const missingElement = !names.has("script-src-elem");
      const missingAttribute = !names.has("script-src-attr");
      if (missingElement || missingAttribute)
        found.push({
          directive:
            missingElement && missingAttribute
              ? "script-src"
              : missingElement
                ? "script-src-elem"
                : "script-src-attr",
          source: null,
          reason:
            missingElement && missingAttribute
              ? "Neither script-src nor default-src is present, so scripts are unrestricted."
              : `No ${missingElement ? "script-src-elem" : "script-src-attr"}, script-src or default-src restricts ${missingElement ? "script elements" : "script attributes"}.`,
        });
    }
    if (!names.has("object-src"))
      found.push({
        directive: "object-src",
        source: null,
        reason:
          "Neither object-src nor default-src is present, so plugin content is unrestricted.",
      });
  }
  return found;
};

const sourceConcern = (
  directive: string,
  source: string,
  nonceOrHash: boolean,
): string | undefined => {
  if (source === "*") return "The wildcard source allows any host.";
  if (NETWORK_SCHEMES.has(source))
    return `The scheme source ${source} allows any host with that scheme.`;
  const script = SCRIPT_DIRECTIVES.has(directive);
  if (script && SCRIPT_SCHEMES.has(source))
    return `The scheme source ${source} allows script content from any ${source} URL.`;
  if (
    source === "'unsafe-inline'" &&
    (STYLE_DIRECTIVES.has(directive) || (script && !nonceOrHash))
  )
    return "'unsafe-inline' allows inline content.";
  if (script && source === "'unsafe-eval'")
    return "'unsafe-eval' allows string evaluation.";
  return undefined;
};
