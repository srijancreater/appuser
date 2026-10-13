import { expect, it } from "vitest";

import { classifyJavaScriptUrlValue } from "./javascriptUrlValues.js";

it.each([
  [
    "https://api.example.com/v1?x=1",
    { url_class: "http", host: "api.example.com" },
  ],
  ["https://", { url_class: "http", host: null }],
  ["wss://api.x.ai/", { url_class: "websocket", host: "api.x.ai" }],
  ["//cdn.example.org/lib.js", { url_class: "http", host: "cdn.example.org" }],
  ["api.x.com", { url_class: "host", host: "api.x.com" }],
  ["x.ai", { url_class: "host", host: "x.ai" }],
  [
    "connectors-gateway.grok.gcp.mouseion.dev",
    { url_class: "host", host: "connectors-gateway.grok.gcp.mouseion.dev" },
  ],
  [
    "localhost.example.com:8080",
    { url_class: "host", host: "localhost.example.com" },
  ],
  ["/v1/bot-template", { url_class: "path", host: null }],
  ["/users/:id?tab=1#top", { url_class: "path", host: null }],
  ["data:image/png;base64,AAAA", { url_class: "data", host: null }],
  ["blob:https://example.com/1", { url_class: "blob", host: null }],
  ["file:///etc/hosts", { url_class: "file", host: null }],
] as const)("classifies %s", (value, expected) => {
  expect(classifyJavaScriptUrlValue(value)).toEqual(expected);
});

it.each([
  "",
  "/",
  "/*",
  "/c",
  "/^a$/",
  "a b.com",
  "README.md",
  "this.app",
  "props.style",
  "app.js.map",
  "index.html",
  "1.2.3",
  "about:blank",
  "mailto:a@example.com",
  "data:",
  "Example.COM",
  "source.md",
  "k8s.pod.name",
  "service.instance.id",
  "team.billing.read",
  "event.target.data",
])("does not classify %j as a URL value", (value) => {
  expect(classifyJavaScriptUrlValue(value)).toBeUndefined();
});
