# Nostr MCP Server

This MCP server contains tools for an LLM to interact witt [Nostr](https://nostr.com) protocol relays.

Current available tools:

- `publish_nostr_event`: Publishes an event to relays
- `fetch_nostr_events`: Queries multiple filters to relays and returns the matching events
- `get_nostr_pubkey`: Returns the corresponding pubkey of private key in [config](./config.toml).
- `list_nostr_relays`: Returns the relays in the [config](./config.toml).
- `get_nip`: Returns a NIPs markdown text by its string ID like `01` or `CC`.
- `connect_relay`: Connects to a relay at runtime.
- `disconnect_relay`: Disconnects from a relay at runtime.
- `relay_info`: Returns NIP-11 information document of a relay.

Possible improvements:

- AUTH message handle: sends auth if it was required.
- NIP-19 entities encode/decode tool.