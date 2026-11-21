import test from "node:test";
import assert from "node:assert/strict";
import { buildDomainsExpression, parseDomainList, parseRewrites } from "../lib/policies.js";

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
