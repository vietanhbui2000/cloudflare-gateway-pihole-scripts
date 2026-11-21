import { isIP } from "node:net";

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
 * Parses rewrite lines in the form "medium.com == 162.159.152.4,162.159.153.4".
 * Each domain may appear once; a later line for the same domain replaces the earlier one.
 * @param {string} text The downloaded file contents.
 * @returns {{ rewrites: { domain: string, ips: string[] }[], invalid: string[] }}
 */
export const parseRewrites = (text) => {
  const rewrites = new Map();
  const invalid = [];

  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || isComment(trimmed)) continue;

    const [left, right, ...rest] = trimmed.split("==");
    const domain = left?.trim().toLowerCase();
    const ips = (right ?? "").split(",").map((ip) => ip.trim()).filter(Boolean);

    if (rest.length || !isValidDomain(domain) || !ips.length || !ips.every((ip) => isIP(ip))) {
      invalid.push(trimmed);
      continue;
    }

    rewrites.set(domain, [...new Set(ips)]);
  }

  return {
    rewrites: [...rewrites].sort(([a], [b]) => a.localeCompare(b)).map(([domain, ips]) => ({ domain, ips })),
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
