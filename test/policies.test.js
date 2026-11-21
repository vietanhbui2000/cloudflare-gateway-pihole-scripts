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

test("parses rewrite lines and rejects malformed ones", () => {
  const text = [
    "medium.com == 162.159.152.4, 162.159.153.4",
    "v6.example.com==2606:4700::6810:84e5",
    "medium.com == 162.159.152.4,162.159.152.4",
    "bad.example.com == 999.1.1.1",
    "noips.example.com ==",
    "missing-separator.com 1.1.1.1",
    "a.com == 1.1.1.1 == 2.2.2.2",
  ].join("\n");
  const { rewrites, invalid } = parseRewrites(text);
  assert.deepEqual(rewrites, [
    { domain: "medium.com", ips: ["162.159.152.4"] },
    { domain: "v6.example.com", ips: ["2606:4700::6810:84e5"] },
  ]);
  assert.equal(invalid.length, 4);
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
