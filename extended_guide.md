# Extended Guide

## Environment variables

Environment variables are like a configuration file. They are stored in a file called `.env` in the same directory as the scripts. You have to create this file yourself (an example file is provided in the repository). Below is a list of the most important environment variables and their descriptions.

### Obtaining your Cloudflare credentials

#### `CLOUDFLARE_ACCOUNT_ID`

You can find your Cloudflare account ID in the [Cloudflare dashboard](https://dash.cloudflare.com/). Click on any domain you own, then on the "Overview" tab. Scroll down to the bottom of the page and you will see your account ID on the right side.

Alternatively, you can copy the account ID from the URL of any page in the Cloudflare dashboard. The URL will look like this:

```text
https://dash.cloudflare.com/1234567890abcdef1234567890abcdef
```

In this example, `1234567890abcdef1234567890abcdef` is the account ID.

#### `CLOUDFLARE_API_TOKEN`

Cloudflare API Token can be created in your [Cloudflare profile](https://dash.cloudflare.com/profile/api-tokens):

1. Click "Create Token" and click "Get Started" in the "Create Custom Token" row.
2. Enter any name for your token
3. Add Zero Trust Read and Edit permissions for your account
4. Click "Continue to summary" and click "Create Token"
5. You will see the created API Token

![Creating API Token](.github/images/create_api_token.png)

#### `CLOUDFLARE_LIST_ITEM_LIMIT`

The Cloudflare list item limit is the maximum number of items (blocked domains) that can be added to Cloudflare. The default value of 300,000 is the maximum allowed by Cloudflare for free accounts. If you pay for Cloudflare Zero Trust, you might be able to increase this value.

### Other

#### `DRY_RUN`

Processes block/allow lists without actually adding/removing domains from Cloudflare. Avoid using this option unless you know what you are doing.

### Personal DNS policies

These run at the end of `npm run cloudflare-create` (or alone with `npm run cloudflare-create:policies`). Each takes one URL. Unlike `ALLOWLIST_URLS` and `BLOCKLIST_URLS`, the domains are written straight into the policy instead of Zero Trust lists, so keep these files short. Leaving a variable unset leaves its policies untouched. If a file has no valid entries, the script stops without changing anything.

#### `ALLOWLIST_URL`

A file of domains (plain, hosts or adblock format) that becomes one **Allow** policy named `Allowlist (manual)`, for example `any(dns.domains[*] in {"analytics.google.com" "example.com"})`. Subdomains match too. Keep this policy above `CGPS Filter Lists` in the dashboard so it wins.

#### `BLOCKLIST_URL`

Same format, becomes one **Block** policy named `Blocklist (manual)`.

#### `REWRITE_URL`

One rewrite per line, `domain == ip[,ip...]`:

```
medium.com == 162.159.152.4,162.159.153.4
```

Each line becomes an **Override** policy named `Rewrite: <domain>` that answers queries for that exact hostname with the given IPs. Removing a line deletes the policy the script created for it.

Policies with these names that already exist are taken over and updated. The script keeps each policy's on/off switch from the dashboard.

After syncing, the script keeps its own policies in this order among themselves: `Allowlist (manual)`, `Blocklist (manual)`, `CGPS Filter Lists`, then the `Rewrite:` policies, so your personal allows win over every block. It only swaps them among the positions they already hold, so policies you created yourself keep their exact positions and are never edited. A correctly ordered list is left alone.

Every policy these scripts write, including `CGPS Filter Lists`, gets the description `Policy managed by CGPS (<owner/repo>).`, filled from `GITHUB_REPOSITORY` in GitHub Actions, or `Policy managed by CGPS.` elsewhere. Rewrite policies are only deleted when their description starts with `Policy managed by CGPS`, so policies made by hand are never removed.

## Example usage

These commands should be run in a terminal.

```bash
# Assumes you have already cloned the repository and installed dependencies such as git and node.js.

# 1. Clone the repository
git clone https://github.com/mrrfv/cloudflare-gateway-pihole-scripts
cd cloudflare-gateway-pihole-scripts # change the current directory to the cloned repository
# 2. Run npm install to install dependencies.
npm install
# 3.1. Copy the example.env file to .env
# Files starting with a dot are hidden by default on Linux and macOS.
cp example.env .env
# 3.2. Edit the .env file and add your Cloudflare credentials.
# (This command varies depending on your system and preferred text editor.)
nano .env
# 4. If this is a subsequent run, execute node cf_gateway_rule_delete.js and node cf_list_delete.js (in order) to delete old data.
# Not needed if setting up for the first time.
node cf_gateway_rule_delete.js
node cf_list_delete.js
# 5. Download the default filter lists.
# If you want to use your own lists, put your blocked and allowed domains in files called "blocklist.txt" and "allowlist.txt" respectively.
node download_lists.js
# 6. Send the filter lists to Cloudflare.
node cf_list_create.js
# 7. Add the Cloudflare firewall rule.
node cf_gateway_rule_create.js
# Set up your DNS settings to use Cloudflare Gateway if you haven't already.
# 8. Profit!
ping google-analytics.com
```
