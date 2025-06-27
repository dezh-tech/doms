# Nostr MCP Server

This MCP server contains tools for an LLM to interact witt [Nostr](https://nostr.com) protocol relays.

Current available tools:

- `publish_nostr_event`: Publishes an event to relays
- `fetch_nostr_events`: Queries multiple filters to relays and returns the matching events
- `get_nostr_pubkey`: Returns the corresponding pubkey of private key in [config](./config.toml).
- `get_nostr_relays`: Returns the relays in the [config](./config.toml).

Possible improvements:

- `get_nip` tool: gets content of an NIP by its number so the agent can read and understand it.
- `connect_relay` too: connects to provided relay.
- AUTH message handle: sends auth if it was required.
