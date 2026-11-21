// Syncs small personal DNS policies from three single-URL sources:
//   ALLOWLIST_URL -> one "allow" policy, domains written inline in the rule
//   BLOCKLIST_URL -> one "block" policy, domains written inline in the rule
//   REWRITE_URL   -> one "override" policy per line, e.g. "medium.com == 162.159.152.4,162.159.153.4"
// Unset variables are skipped and their policies are left alone.
import { deleteZeroTrustRule, getZeroTrustRules, saveDNSPolicy } from "./lib/api.js";
import {
  BLOCK_PAGE_ENABLED,
  DRY_RUN,
  POLICY_DESCRIPTION,
  POLICY_DESCRIPTION_PREFIX,
  POLICY_NAME,
  POLICY_ALLOWLIST_URL,
  POLICY_BLOCKLIST_URL,
  POLICY_REWRITE_URL,
} from "./lib/constants.js";
import {
  buildDomainsExpression,
  buildHostExpression,
  parseDomainList,
  parseRewrites,
} from "./lib/policies.js";
import { notifyWebhook } from "./lib/utils.js";

const download = async (variable, url) => {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`${variable}: download failed with HTTP ${response.status} (${url})`);
  return response.text();
};

// An empty result usually means a broken file or URL, not an intent to drop every entry.
// Stop before touching anything; unset the variable to stop managing those policies.
const checkParsed = (variable, count, invalid) => {
  if (invalid.length) {
    console.warn(`${variable}: skipped ${invalid.length} invalid line(s):\n  ${invalid.slice(0, 20).join("\n  ")}`);
  }
  if (!count) throw new Error(`${variable}: no valid entries found, so no policies were changed.`);
};

const policies = [];

if (POLICY_ALLOWLIST_URL) {
  const { domains, invalid } = parseDomainList(await download("ALLOWLIST_URL", POLICY_ALLOWLIST_URL), true);
  checkParsed("ALLOWLIST_URL", domains.length, invalid);
  policies.push({
    name: POLICY_NAME.ALLOWLIST,
    description: POLICY_DESCRIPTION,
    action: "allow",
    traffic: buildDomainsExpression(domains),
    rule_settings: {},
  });
}

if (POLICY_BLOCKLIST_URL) {
  const { domains, invalid } = parseDomainList(await download("BLOCKLIST_URL", POLICY_BLOCKLIST_URL));
  checkParsed("BLOCKLIST_URL", domains.length, invalid);
  policies.push({
    name: POLICY_NAME.BLOCKLIST,
    description: POLICY_DESCRIPTION,
    action: "block",
    traffic: buildDomainsExpression(domains),
    rule_settings: { block_page_enabled: BLOCK_PAGE_ENABLED },
  });
}

if (POLICY_REWRITE_URL) {
  const { rewrites, invalid } = parseRewrites(await download("REWRITE_URL", POLICY_REWRITE_URL));
  checkParsed("REWRITE_URL", rewrites.length, invalid);
  for (const { domain, ips } of rewrites) {
    policies.push({
      name: `${POLICY_NAME.REWRITE_PREFIX}${domain}`,
      description: POLICY_DESCRIPTION,
      action: "override",
      traffic: buildHostExpression(domain),
      rule_settings: { override_ips: ips },
    });
  }
}

if (!policies.length) {
  console.log("None of ALLOWLIST_URL, BLOCKLIST_URL or REWRITE_URL is set. Nothing to do.");
  process.exit(0);
}

if (DRY_RUN) {
  for (const { name, action, traffic, rule_settings } of policies) {
    console.log(`[${action}] ${name}\n  ${traffic}${rule_settings.override_ips ? `\n  -> ${rule_settings.override_ips.join(", ")}` : ""}`);
  }
  console.log(`\nDry run complete: ${policies.length} policies parsed, nothing sent to Cloudflare.`);
  process.exit(0);
}

const { result: rules = [] } = await getZeroTrustRules();
const rulesByName = new Map(rules.map((rule) => [rule.name, rule]));
const counts = { created: 0, updated: 0, unchanged: 0, deleted: 0 };

for (const policy of policies) {
  const existing = rulesByName.get(policy.name);
  if (existing && !existing.description?.startsWith(POLICY_DESCRIPTION_PREFIX)) {
    console.log(`Taking over existing policy "${policy.name}" (made outside this script).`);
  }
  const outcome = await saveDNSPolicy(existing, policy);
  counts[outcome]++;
  if (outcome !== "unchanged") console.log(`${outcome[0].toUpperCase()}${outcome.slice(1)} "${policy.name}"`);
}

// Remove rewrite policies this script created earlier whose line is gone from REWRITE_URL.
// Rules without the CGPS description prefix (made by hand) are never deleted.
if (POLICY_REWRITE_URL) {
  const wanted = new Set(policies.map(({ name }) => name));
  const stale = rules.filter(
    (rule) =>
      rule.name.startsWith(POLICY_NAME.REWRITE_PREFIX) &&
      rule.description?.startsWith(POLICY_DESCRIPTION_PREFIX) &&
      !wanted.has(rule.name)
  );
  for (const rule of stale) {
    console.log(`Deleting "${rule.name}" (no longer in REWRITE_URL)`);
    await deleteZeroTrustRule(rule.id);
    counts.deleted++;
  }
}

const summary = Object.entries(counts).map(([key, value]) => `${value} ${key}`).join(", ");
console.log(`DNS policies: ${summary}`);
await notifyWebhook(`CF Policy Sync script finished running (${summary})`);
