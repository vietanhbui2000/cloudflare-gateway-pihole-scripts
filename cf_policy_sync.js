// Syncs manual DNS policies from three short, hand-written lists. Each variable takes entries
// directly, one per line, or the URL of a filter list:
//   ALLOWED_DOMAINS   -> one "allow" policy, domains written inline in the rule
//   BLOCKED_DOMAINS   -> one "block" policy, domains written inline in the rule
//   REWRITTEN_DOMAINS -> one "override" policy per domain, from hosts lines, e.g. "162.159.152.4 medium.com"
// Unset variables are skipped and their policies are left alone.
// After syncing, CGPS policies are kept in order among themselves: allowed, blocked, CGPS Filter Lists, rewritten.
import { deleteZeroTrustRule, getZeroTrustRules, saveDNSPolicy, updateZeroTrustRulePrecedence } from "./lib/api.js";
import {
  BLOCK_PAGE_ENABLED,
  DRY_RUN,
  POLICY_DESCRIPTION,
  POLICY_NAME,
  ALLOWED_DOMAINS,
  BLOCKED_DOMAINS,
  REWRITTEN_DOMAINS,
} from "./lib/constants.js";
import {
  buildDomainsExpression,
  buildHostExpression,
  isSourceUrl,
  parseDomainList,
  parseRewrites,
  planPolicyOrder,
} from "./lib/policies.js";
import { notifyWebhook } from "./lib/utils.js";

// Returns the list text: downloaded when the variable is a single URL, otherwise the variable itself.
const readSource = async (variable, value) => {
  if (!isSourceUrl(value)) return value;
  const response = await fetch(value);
  if (!response.ok) throw new Error(`${variable}: download failed with HTTP ${response.status} (${value})`);
  return response.text();
};

// An empty result usually means a broken list or URL, not an intent to drop every entry.
// Stop before touching anything; unset the variable to stop managing those policies.
const checkParsed = (variable, count, invalid) => {
  if (invalid.length) {
    console.warn(`${variable}: skipped ${invalid.length} invalid line(s):\n  ${invalid.slice(0, 20).join("\n  ")}`);
  }
  if (!count) throw new Error(`${variable}: no valid entries found, so no policies were changed.`);
};

const policies = [];

if (ALLOWED_DOMAINS) {
  const { domains, invalid } = parseDomainList(await readSource("ALLOWED_DOMAINS", ALLOWED_DOMAINS), true);
  checkParsed("ALLOWED_DOMAINS", domains.length, invalid);
  policies.push({
    name: POLICY_NAME.ALLOWED_DOMAINS,
    description: POLICY_DESCRIPTION,
    action: "allow",
    traffic: buildDomainsExpression(domains),
    rule_settings: {},
  });
}

if (BLOCKED_DOMAINS) {
  const { domains, invalid } = parseDomainList(await readSource("BLOCKED_DOMAINS", BLOCKED_DOMAINS));
  checkParsed("BLOCKED_DOMAINS", domains.length, invalid);
  policies.push({
    name: POLICY_NAME.BLOCKED_DOMAINS,
    description: POLICY_DESCRIPTION,
    action: "block",
    traffic: buildDomainsExpression(domains),
    rule_settings: { block_page_enabled: BLOCK_PAGE_ENABLED },
  });
}

if (REWRITTEN_DOMAINS) {
  const { rewrites, invalid } = parseRewrites(await readSource("REWRITTEN_DOMAINS", REWRITTEN_DOMAINS));
  checkParsed("REWRITTEN_DOMAINS", rewrites.length, invalid);
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
  console.log("None of ALLOWED_DOMAINS, BLOCKED_DOMAINS or REWRITTEN_DOMAINS is set. Nothing to do.");
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
const counts = { created: 0, updated: 0, unchanged: 0, deleted: 0, reordered: 0 };

for (const policy of policies) {
  const outcome = await saveDNSPolicy(rulesByName.get(policy.name), policy);
  counts[outcome]++;
  if (outcome !== "unchanged") console.log(`${outcome[0].toUpperCase()}${outcome.slice(1)} "${policy.name}"`);
}

// Remove CGPS rewrite policies whose domain is gone from REWRITTEN_DOMAINS.
// Policies made by hand don't use the CGPS prefix, so they're never deleted.
if (REWRITTEN_DOMAINS) {
  const wanted = new Set(policies.map(({ name }) => name));
  const stale = rules.filter((rule) => rule.name.startsWith(POLICY_NAME.REWRITE_PREFIX) && !wanted.has(rule.name));
  for (const rule of stale) {
    console.log(`Deleting "${rule.name}" (no longer in REWRITTEN_DOMAINS)`);
    await deleteZeroTrustRule(rule.id);
    counts.deleted++;
  }
}

// Keep CGPS policies in policyRank order; policies made by hand keep their positions.
// New rules land at the bottom, so this runs after every create. Precedence values must be unique,
// so moved rules first go to temporary values above every rule, then to their final values;
// this avoids clashing with a rule that hasn't moved yet.
const { result: currentRules = [] } = await getZeroTrustRules();
const moves = planPolicyOrder(currentRules);
if (moves.length) {
  const temporaryBase = Math.max(...currentRules.map((rule) => rule.precedence)) + 1000;
  for (const [index, { rule }] of moves.entries()) {
    await updateZeroTrustRulePrecedence(rule, temporaryBase + index);
  }
  for (const { rule, precedence } of moves) {
    await updateZeroTrustRulePrecedence(rule, precedence);
  }
  counts.reordered = moves.length;
  console.log(`Reordered ${moves.length} CGPS policies: ${moves.map(({ rule }) => `"${rule.name}"`).join(", ")}`);
}

const summary = Object.entries(counts).map(([key, value]) => `${value} ${key}`).join(", ");
console.log(`DNS policies: ${summary}`);
await notifyWebhook(`CF Policy Sync script finished running (${summary})`);
