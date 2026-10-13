import { IANA_COUNTRY_CODE_TOP_LEVEL_DOMAINS } from "./ianaCountryCodeTopLevelDomains.js";

/** URL-like value classes recognized in JavaScript string data. */
export type JavaScriptUrlClass =
  | "http"
  | "websocket"
  | "host"
  | "path"
  | "data"
  | "blob"
  | "file";

/** Syntax class of one URL-like value and the host it names, if any. */
export interface JavaScriptUrlClassification {
  readonly url_class: JavaScriptUrlClass;
  readonly host: string | null;
}

// Labels that end source and asset file names rather than DNS names.
const FILE_EXTENSION_LABELS = new Set([
  "cjs",
  "css",
  "cts",
  "htm",
  "html",
  "js",
  "json",
  "jsx",
  "mjs",
  "mts",
  "ts",
  "tsx",
]);

// Generic top-level domains accepted for host names written without a scheme.
// Most newer generic TLDs are ordinary words (`name`, `read`, `data`) that end
// dotted attribute keys and permission scopes far more often than host names.
const GENERIC_TLDS = new Set([
  "app",
  "biz",
  "cloud",
  "com",
  "dev",
  "edu",
  "gov",
  "info",
  "int",
  "mil",
  "net",
  "org",
  "tech",
  "xyz",
]);

// Country codes that end attribute keys and file names more often than hosts.
const AMBIGUOUS_COUNTRY_CODES = new Set(["id"]);
const FILE_EXTENSION_COUNTRY_CODES = new Set([
  "cc",
  "md",
  "mk",
  "ml",
  "pl",
  "ps",
  "py",
  "rs",
  "sh",
  "so",
]);
const TWO_LABEL_GENERIC_TLDS = new Set([
  "biz",
  "com",
  "edu",
  "gov",
  "info",
  "int",
  "mil",
  "net",
  "org",
]);

const DNS_NAME =
  /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?::\d{1,5})?$/u;
const URL_PATH = /^\/[\w\-.~!$&'+,;=:@%/?#]*$/u;
const DATA_URL = /^data:(?:[a-z]+\/[a-z0-9.+-]+)?(?:;[^,]*)?,/iu;

/**
 * Classify a string by URL syntax alone. Host-only values are DNS names under
 * an IANA country-code or a common generic top-level domain; the
 * classification is syntactic and does not establish that the application
 * contacts the host.
 */
export const classifyJavaScriptUrlValue = (
  value: string,
): JavaScriptUrlClassification | undefined => {
  if (value.length < 2 || /[\s\p{Cc}]/u.test(value)) return undefined;
  const lower = value.toLowerCase();
  if (lower.startsWith("http://") || lower.startsWith("https://"))
    return { url_class: "http", host: urlHost(value) };
  if (lower.startsWith("ws://") || lower.startsWith("wss://"))
    return { url_class: "websocket", host: urlHost(value) };
  if (DATA_URL.test(value)) return { url_class: "data", host: null };
  if (lower.startsWith("blob:") && value.length > 5)
    return { url_class: "blob", host: null };
  if (lower.startsWith("file:/")) return { url_class: "file", host: null };
  if (value.startsWith("//")) {
    const host = urlHost(`https:${value}`);
    return host !== null && isDnsHost(host)
      ? { url_class: "http", host }
      : undefined;
  }
  if (value.startsWith("/"))
    return URL_PATH.test(value) && /[a-z0-9].*[a-z0-9]/isu.test(value)
      ? { url_class: "path", host: null }
      : undefined;
  return isDnsHost(value)
    ? { url_class: "host", host: value.replace(/:\d+$/u, "") }
    : undefined;
};

const urlHost = (value: string): string | null => {
  try {
    const host = new URL(value).hostname;
    return host === "" ? null : host;
  } catch (cause: unknown) {
    // A URL prefix such as "https://" names no host yet.
    void cause;
    return null;
  }
};

const isDnsHost = (value: string): boolean => {
  if (!DNS_NAME.test(value)) return false;
  const labels = value.replace(/:\d+$/u, "").split(".");
  const tld = labels.at(-1) ?? "";
  if (labels.slice(0, -1).some((label) => FILE_EXTENSION_LABELS.has(label)))
    return false;
  if (GENERIC_TLDS.has(tld))
    return labels.length > 2 || TWO_LABEL_GENERIC_TLDS.has(tld);
  return (
    IANA_COUNTRY_CODE_TOP_LEVEL_DOMAINS.has(tld) &&
    !AMBIGUOUS_COUNTRY_CODES.has(tld) &&
    (labels.length > 2 || !FILE_EXTENSION_COUNTRY_CODES.has(tld))
  );
};
