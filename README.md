# Cloudflare Gateway Pi-hole Scripts (CGPS)

[![Update Filter Lists](https://github.com/vietanhbui2000/cloudflare-gateway-pihole-scripts/actions/workflows/update-filter-lists.yml/badge.svg)](https://github.com/vietanhbui2000/cloudflare-gateway-pihole-scripts/actions/workflows/update-filter-lists.yml)

A fork of [cloudflare-gateway-pihole-scripts](https://github.com/mrrfv/cloudflare-gateway-pihole-scripts) by [mrrfv](https://github.com/mrrfv).

Cloudflare Gateway allows you to create custom rules to filter HTTP, DNS, and network traffic based on your firewall policies. This is a collection of scripts that can be used to get a similar experience as if you were using Pi-hole, but with Cloudflare Gateway - so no servers to maintain or need to buy a Raspberry Pi!

This fork adds `ALLOWED_DOMAINS`, `BLOCKED_DOMAINS` and `REWRITTEN_DOMAINS`. Each takes domains entered directly, one per line, or the URL of a filter list, and turns them into the `CGPS Allowed Domains`, `CGPS Blocked Domains` and `CGPS Rewrite: <domain>` DNS policies. After each run, these policies and `CGPS Filter Lists` stay in that priority order, while policies you create yourself keep their place.

See the [extended guide](./extended_guide.md) for details.

## License

MIT license. See [`LICENSE`](./LICENSE) for more information.
