import test from "node:test";
import assert from "node:assert/strict";
import { buildDomainsExpression, parseDomainList, parseRewrites, planPolicyOrder } from "../lib/policies.js";

test("parses mixed domain list formats into a sorted, unique list", () => {
  const text = [
    "# comment",
    "analytics.google.com",
    "0.0.0.0 ads.example.com",
    "||tracker.example.com^",
    "Analytics.Google.com",
    "not a domain",
    "",
  ].join("\n");
  const { domains, invalid } = parseDomainList(text);
  assert.deepEqual(domains, ["ads.example.com", "analytics.google.com", "tracker.example.com"]);
  assert.deepEqual(invalid, ["not a domain"]);
});

test("accepts adblock exceptions only for allowlists", () => {
  assert.deepEqual(parseDomainList("@@||cdn.example.com^", true).domains, ["cdn.example.com"]);
  assert.deepEqual(parseDomainList("@@||cdn.example.com^").domains, []);
});

test("builds the inline Gateway expression", () => {
  assert.equal(
    buildDomainsExpression(["a.example.com", "b.example.com"]),
    'any(dns.domains[*] in {"a.example.com" "b.example.com"})'
  );
});

test("parses hosts lines into one rewrite per domain with merged IPs", () => {
  const text = [
    "# Rewrites",
    "162.159.152.4 medium.com",
    "162.159.153.4\tMedium.com # second IP",
    "162.159.152.4 medium.com",
    "2606:4700::6810:84e5 v6.example.com",
    "1.2.3.4 a.example.com b.example.com",
  ].join("\n");
  const { rewrites, invalid } = parseRewrites(text);
  assert.deepEqual(rewrites, [
    { domain: "a.example.com", ips: ["1.2.3.4"] },
    { domain: "b.example.com", ips: ["1.2.3.4"] },
    { domain: "medium.com", ips: ["162.159.152.4", "162.159.153.4"] },
    { domain: "v6.example.com", ips: ["2606:4700::6810:84e5"] },
  ]);
  assert.deepEqual(invalid, []);
});

test("rejects malformed hosts lines", () => {
  const text = [
    "medium.com 162.159.152.4",
    "999.1.1.1 bad.example.com",
    "1.1.1.1",
    "127.0.0.1 localhost",
    "1.1.1.1 good.example.com not_a_domain",
  ].join("\n");
  const { rewrites, invalid } = parseRewrites(text);
  assert.deepEqual(rewrites, []);
  assert.equal(invalid.length, 5);
});

const rule = (name, precedence, filters = ["dns"]) => ({ name, precedence, filters });
const plan = (rules) => planPolicyOrder(rules).map(({ rule, precedence }) => [rule.name, precedence]);

test("leaves the current dashboard order alone", () => {
  const rules = [
    rule("Allowlist (manual)", 1),
    rule("Blocklist (manual)", 2),
    rule("CGPS Filter Lists", 3),
    rule("Block content categories (Cloudflare)", 4),
    rule("Block security categories (Cloudflare)", 5),
    rule("Rewrite: medium.com", 6),
  ];
  assert.deepEqual(plan(rules), []);
});

test("swaps CGPS policies among their own slots without moving other policies", () => {
  const rules = [
    rule("Allowlist (manual)", 1),
    rule("Rewrite: medium.com", 2),
    rule("Block content categories (Cloudflare)", 3),
    rule("CGPS Filter Lists", 4),
    rule("HTTP rule", 5, ["http"]),
  ];
  assert.deepEqual(plan(rules), [
    ["CGPS Filter Lists", 2],
    ["Rewrite: medium.com", 4],
  ]);
});

test("moves a newly created allowlist above the other CGPS policies", () => {
  const rules = [
    rule("Blocklist (manual)", 1),
    rule("Other", 2),
    rule("CGPS Filter Lists", 3),
    rule("Rewrite: b.com", 4),
    rule("Rewrite: a.com", 5),
    rule("Allowlist (manual)", 1000950),
  ];
  assert.deepEqual(plan(rules), [
    ["Allowlist (manual)", 1],
    ["Blocklist (manual)", 3],
    ["CGPS Filter Lists", 4],
    ["Rewrite: b.com", 5],
    ["Rewrite: a.com", 1000950],
  ]);
});
