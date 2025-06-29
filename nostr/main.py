from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from dataclasses import dataclass

import httpx
from mcp.server.fastmcp import FastMCP, Context
from nostr.key import PrivateKey
from nostr.relay_manager import RelayManager
from nostr.filter import Filters
from nostr.event import Event
import toml
from typing import List
import uuid


@dataclass
class AppContext:
    privkey: PrivateKey
    relay_manager: RelayManager


@asynccontextmanager
async def app_lifespan(server: FastMCP) -> AsyncIterator[AppContext]:
    config = toml.load("config.toml")
    privkey = PrivateKey.from_hex(config["nostr"]["private_key"])
    relay_manager = RelayManager()
    for url in config["nostr"]["relays"]:
        relay_manager.add_relay(url)
    relay_manager.open_connections()
    try:
        yield AppContext(privkey=privkey, relay_manager=relay_manager)
    finally:
        relay_manager.close_connections()


mcp = FastMCP("Nostr MCP Server", lifespan=app_lifespan)


@mcp.tool()
def publish_nostr_event(
    content: str, kind: int = 1, tags: list[str] | None = None
) -> str:
    """
    Publish a Nostr event (per NIP‑01) to configured relays.

    Nostr (“Notes and Other Stuff Transmitted by Relays”) is a simple,
    censorship‑resistant protocol where each client holds an EC key pair
    and signs JSON events (per NIP‑01) before sending them to relays.

    A Nostr event contains:
      - `id`: sha256 of serialized [0, pubkey, created_at, kind, tags, content]
      - `pubkey`: hex‑encoded secp256-k1 public key of the author
      - `created_at`: UNIX timestamp in seconds
      - `kind`: integer indicating event type between 0 and 65535 (e.g., 1 = short text note)
      - `tags`: list of tag arrays (e.g., ["e", <event‑id>], ["p", <pubkey>])
      - `content`: arbitrary string
      - `sig`: Schnorr signature of the event hash

    This function:
      1. Constructs an event with `content`, `kind`, and optional `tags`
      2. Uses the server’s configured private key to compute `id` and `sig`
      3. Publishes the signed event to all configured relays

    Args:
        content (str): the text or JSON content of the event
        kind (int, optional): Nostr event kind (defaults to 1 = short text note)
        tags (list[str], optional): list of Nostr tags (arrays of strings),
            e.g. `[["e", "<event‑id>"], ["p", "<pubkey>"]]`

    Returns:
        str: the hex‑encoded `id` of the published event
    """
    ctx: Context = mcp.get_context()
    app_ctx: AppContext = ctx.request_context.lifespan_context

    event = Event(
        content=content,
        kind=kind,
        pubkey=app_ctx.privkey.public_key.hex(),
        tags=tags or [],
    )
    event.signature = app_ctx.privkey.sign_event(event)
    app_ctx.relay_manager.publish_event(event)
    return event.id


@mcp.tool()
def fetch_nostr_events(filters: Filters) -> List[Event]:
    """
    Subscribe to relays using standard Nostr filters (NIP‑01) and return matching Event objects.

    Per NIP‑01, relays accept JSON `REQ` subscriptions with filters containing:
      - `ids`: list of exact 64-char event IDs
      - `authors`: list of lowercase pubkeys
      - `kinds`: list of event kind integers
      - `#<tag>`: tag-based filters (e.g. `#e`, `#p`) for matching tag values
      - `since`, `until`: UNIX timestamps (inclusive) for event creation time
      - `limit`: maximum number of events returned in the initial batch
      - `search`: full-text search query

    Matching rules:
      - For arrays (`ids`, `authors`, `kinds`, `#e`, etc.), at least one element must match
      - `since ≤ created_at ≤ until`
      - Multiple filters = logical OR; within a filter = logical AND

    This tool:
      1. Accepts one or more `Filter` instances from `python-nostr`
      2. Sends a subscription (`REQ`) to all configured relays
      3. Waits briefly to collect both stored and live events
      4. Returns a list of `nostr.event.Event` instances

    Args:
        filters (Filter or list[Filter]): Pre-built filter(s) using `nostr.filter.Filter`,
            e.g. `Filter().authors([pubkey]).kinds([1]).since(ts).limit(50)`

    Returns:
        List[nostr.event.Event]: Fully parsed Event objects matching the filter criteria.
    """
    ctx: Context = mcp.get_context()
    app_ctx = ctx.request_context.lifespan_context

    sub_id = uuid.uuid4().hex
    rm: RelayManager = app_ctx.relay_manager

    rm.add_subscription(sub_id, filters)

    events: List[Event] = []
    pool = rm.message_pool
    while pool.has_events():
        ev: Event = pool.get_event().event
        if not ev.verify():
            continue

        if not filters.match(ev):
            continue

        events.append(ev.event)

    return events


@mcp.tool()
def get_nostr_pubkey() -> str:
    """
    Return the hex-encoded public key corresponding to the server’s private key.

    In Nostr, identity is determined by a secp256k1 key pair. The public key (hex)
    is used to identify the author of events.

    Returns:
        str: hex-encoded public key derived from stored private key.
    """
    ctx: Context = mcp.get_context()
    app_ctx = ctx.request_context.lifespan_context
    return app_ctx.privkey.public_key.hex()


@mcp.tool()
def list_nostr_relays() -> List[str]:
    """
    Return the list of relay URLs that the server is currently connected to.

    Nostr clients maintain connections to multiple relays for publishing and subscribing.
    This tool lists the configured relay endpoints managed in the MCP server lifespan.

    Returns:
        List[str]: list of websocket URLs (e.g. "wss://relay.nostr.info") currently in use.
    """
    ctx: Context = mcp.get_context()
    app_ctx = ctx.request_context.lifespan_context
    return list(app_ctx.relay_manager.relays.keys())


@mcp.tool()
async def get_nip(ctx: Context[AppContext], nip_id: str) -> str:
    """
    Fetches the content of a specified Nostr Implementation Possibility (NIP), returning its full markdown text.

    NIP IDs follow the pattern:
      - Numeric NIPs: e.g., "01", "07" — always zero-padded to two digits.
      - Alphanumeric NIPs (Hexadecimal): e.g., "CC", "7D".

    Parameters:
        nip_id (str): The NIP identifier (zero-padded number or uppercase alphanumeric),
                      e.g. "01", "07", "7D", "CC".

    Returns:
        str: Full markdown text of the NIP document.

    Context:
      NIPs ("Nostr Implementation Possibilities") are specifications that define possible features or behaviors
      in Nostr-compatible software. This tool helps the you retrieve and understand
      protocol standards dynamically.
    """
    url = f"https://raw.githubusercontent.com/nostr-protocol/nips/master/{nip_id}.md"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url)
    resp.raise_for_status()
    return resp.text


@mcp.tool()
async def connect_relay(ctx: Context[AppContext], relay_url: str) -> bool:
    """
    Dynamically connects the running server to an additional Nostr relay.

    Parameters:
        relay_url (str): WebSocket URL of the relay to connect, e.g. "wss://relay.example.com".

    Returns:
        bool: True if the connection was successfully established, False otherwise.

    Behavior:
      Adds and connects to the given relay URL via `RelayManager`.
    """
    rm: RelayManager = ctx.app.relay_manager
    if relay_url in rm.relays:
        return True
    
    ctx.app.relay_manager.add_relay(relay_url)
    ctx.app.relay_manager.open_connections()
    return relay_url in ctx.app.relay_manager.connection_statuses

@mcp.tool()
async def disconnect_relay(ctx: Context[AppContext], relay_url: str) -> bool:
    """
    Disconnects from a specified Nostr relay at runtime.

    Parameters:
        relay_url (str): WebSocket URL of the relay to disconnect, e.g. "wss://relay.example.com".

    Returns:
        bool: True if the relay was found and disconnected successfully, False otherwise.

    Behavior:
      Closes the WebSocket connection via RelayManager and removes its entry, allowing the server 
      to dynamically manage its relay set.
    """
    rm: RelayManager = ctx.app.relay_manager
    if relay_url not in rm.relays:
        return False

    rm.close_relay(relay_url)
    removed = relay_url not in rm.connection_statuses or not rm.connection_statuses.get(relay_url, True)
    return removed


@mcp.tool()
async def relay_info(ctx: Context[AppContext], relay_url: str) -> dict:
    """
    Retrieves metadata from a Nostr relay using NIP-11 (Relay Information Document).

    Parameters:
        relay_url (str): The WebSocket URL of the relay (e.g., "wss://relay.example.com").

    Returns:
        dict: Parsed NIP-11 metadata

    Context:
      NIP-11 defines a JSON document available via HTTP(S) (same host as the WebSocket relay) that describes
      relay capabilities—such as supported NIPs, software version, contact info and more.
    """
    http_url = relay_url.replace("ws://", "http://").replace("wss://", "https://")
    async with httpx.AsyncClient() as client:
        resp = await client.get(http_url, headers={"Accept": "application/nostr+json"})
        resp.raise_for_status()
        info = resp.json()
    return info
