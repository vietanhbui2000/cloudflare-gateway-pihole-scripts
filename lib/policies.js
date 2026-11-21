import { isIP } from "node:net";

import { POLICY_NAME } from "./constants.js";
import { normalizeDomain } from "./helpers.js";
import { isComment, isValidDomain } from "./utils.js";

/**
 * Parses a small allowlist or blocklist into a sorted, de-duplicated domain list.
 * Accepts the same line formats as the big lists (plain, hosts, adblock), so one
 * file can be written once and used by either flow.
 * @param {string} text The downloaded file contents.
 * @param {boolean} isAllowlisting Whether "@@||" adblock exceptions should be accepted.
 * @returns {{ domains: string[], invalid: string[] }}
 */
export const parseDomainList = (text, isAllowlisting = false) => {
  const domains = new Set();
  const invalid = [];

  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || isComment(trimmed)) continue;

    const domain = normalizeDomain(trimmed, isAllowlisting).toLowerCase();
    if (isValidDomain(domain)) domains.add(domain);
    else invalid.push(trimmed);
  }

  return { domains: [...domains].sort(), invalid };
};

/**
 * Parses rewrites written as standard hosts lines: "162.159.152.4 medium.com".
 * A line may list several domains after the IP, and a domain with several IPs repeats on one line per IP;
 * all IPs for a domain are merged. Text after "#" is a comment, as in /etc/hosts.
 * @param {string} text The downloaded file contents.
 * @returns {{ rewrites: { domain: string, ips: string[] }[], invalid: string[] }}
 */
export const parseRewrites = (text) => {
  const rewrites = new Map();
  const invalid = [];

  for (const line of text.split("\n")) {
    const trimmed = line.split("#")[0].trim();
    if (!trimmed || isComment(trimmed)) continue;

    const [ip, ...domains] = trimmed.split(/\s+/);
    const lowercased = domains.map((domain) => domain.toLowerCase());

    if (!isIP(ip) || !lowercased.length || !lowercased.every((domain) => isValidDomain(domain))) {
      invalid.push(trimmed);
      continue;
    }

    for (const domain of lowercased) {
      if (!rewrites.has(domain)) rewrites.set(domain, new Set());
      rewrites.get(domain).add(ip);
    }
  }

  return {
    rewrites: [...rewrites].sort(([a], [b]) => a.localeCompare(b)).map(([domain, ips]) => ({ domain, ips: [...ips] })),
    invalid,
  };
};

/**
 * Builds a Gateway expression that matches the domains and all their subdomains.
 * Example: ["a.com", "b.com"] => any(dns.domains[*] in {"a.com" "b.com"})
 * @param {string[]} domains Valid, lowercase domains.
 * @returns {string}
 */
export const buildDomainsExpression = (domains) =>
  `any(dns.domains[*] in {${domains.map((domain) => `"${domain}"`).join(" ")}})`;

/**
 * Builds a Gateway expression that matches one exact hostname, as the dashboard's "Host" selector does.
 * @param {string} domain A valid, lowercase domain.
 * @returns {string}
 */
export const buildHostExpression = (domain) => `dns.fqdn == "${domain}"`;

/**
 * Where a CGPS policy must sit relative to the other CGPS policies: manual allows first so they beat
 * every block, then manual blocks, then the big filter lists, then rewrites.
 * Returns undefined for policies CGPS doesn't manage, which are never reordered.
 * @param {string} name The policy name.
 * @returns {number|undefined}
 */
export const policyRank = (name) => {
  if (name === POLICY_NAME.ALLOWLIST) return 0;
  if (name === POLICY_NAME.BLOCKLIST) return 1;
  if (name === POLICY_NAME.FILTER_LISTS) return 2;
  if (name.startsWith(POLICY_NAME.REWRITE_PREFIX)) return 3;
};

/**
 * Plans the precedence changes that put CGPS DNS policies in policyRank order.
 * CGPS policies only swap among the precedence values they already hold, so every other policy
 * keeps its exact position and is never updated. Rewrites keep their order among themselves.
 * Example: Allowlist=1, Rewrite=2, Other=3, Filter Lists=4 => Filter Lists gets 2, Rewrite gets 4, Other stays 3.
 * @param {Object[]} rules All Gateway rules, as returned by the API.
 * @returns {{ rule: Object, precedence: number }[]} Only the rules whose precedence changes.
 */
export const planPolicyOrder = (rules) => {
  const managed = rules
    .filter((rule) => rule.filters?.includes("dns") && policyRank(rule.name) !== undefined)
    .sort((a, b) => a.precedence - b.precedence);
  const desired = [...managed].sort((a, b) => policyRank(a.name) - policyRank(b.name) || a.precedence - b.precedence);

  return desired
    .map((rule, index) => ({ rule, precedence: managed[index].precedence }))
    .filter(({ rule, precedence }) => rule.precedence !== precedence);
};
