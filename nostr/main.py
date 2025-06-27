from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from dataclasses import dataclass

from mcp.server.fastmcp import FastMCP, Context
from nostr.key import PrivateKey
from nostr.relay_manager import RelayManager
from nostr.filter import FiltersList, Filter
from nostr.event import Event
import toml
from typing import List, Union
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
def fetch_nostr_events(filters: Union[Filter, List[Filter]]) -> List[Event]:
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

    fltr_list = FiltersList(filters if isinstance(filters, list) else [filters])
    sub_id = uuid.uuid4().hex
    rm = app_ctx.relay_manager

    rm.add_subscription_on_all_relays(sub_id, fltr_list)
    rm.run_sync(timeout=2)

    events: List[Event] = []
    pool = rm.message_pool
    while pool.has_events():
        ev_msg = pool.get_event()
        events.append(ev_msg.event)

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
