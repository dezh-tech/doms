#!/usr/bin/env python3
"""
Blossom Protocol MCP Server

A Model Context Protocol (MCP) server implementation for the Blossom protocol,
which provides decentralized blob storage on Nostr-compatible media servers.

Blossom allows users to store and retrieve binary data (images, videos, etc.)
using SHA-256 hashes as addresses, with Nostr event-based authentication.
"""

import asyncio
import hashlib
import json
import logging
import time
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import urljoin, urlparse

import httpx
from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server
from mcp.types import (
    CallToolResult,
    GetPromptResult,
    ListPromptsResult,
    ListToolsResult,
    Prompt,
    TextContent,
    Tool,
)
from nostr.event import Event, EventKind
from nostr.key import PrivateKey
from nostr.relay_manager import RelayManager
from pydantic import BaseModel

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Blossom-specific event kinds
BLOSSOM_AUTH_KIND = 24242  # BUD-01: Authorization events
REPORT_KIND = 1984  # NIP-56/BUD-09: Report events
USER_SERVER_LIST_KIND = 10063  # BUD-03: User server list


class BlobDescriptor(BaseModel):
    """Represents a blob descriptor as returned by Blossom servers."""
    sha256: str
    size: int
    type: str
    url: str
    uploaded: Optional[int] = None
    pubkey: Optional[str] = None


class BlossomServer:
    """Core Blossom protocol client implementation."""
    
    def __init__(self, base_url: str, private_key: Optional[PrivateKey] = None):
        self.base_url = base_url.rstrip('/')
        self.private_key = private_key or PrivateKey()
        self.client = httpx.AsyncClient(timeout=30.0)
        
    def get_pubkey(self) -> str:
        """Get the public key in hex format."""
        return self.private_key.public_key.hex()
    
    def _calculate_sha256(self, data: bytes) -> str:
        """Calculate SHA-256 hash of data."""
        return hashlib.sha256(data).hexdigest()
    
    def _create_auth_event(
        self, 
        verb: str, 
        blob_hash: Optional[str] = None,
        expiration: Optional[int] = None
    ) -> Event:
        """Create a Blossom authorization event (kind 24242)."""
        tags = [["t", verb]]
        
        if blob_hash:
            tags.append(["x", blob_hash])
        
        if expiration:
            tags.append(["expiration", str(expiration)])
            
        # Add current timestamp
        tags.append(["created_at", str(int(time.time()))])
        
        event = Event(
            kind=BLOSSOM_AUTH_KIND,
            content="",
            tags=tags,
            created_at=int(time.time())
        )
        
        event.sign(self.private_key.hex())
        return event
    
    def _get_auth_headers(self, auth_event: Event) -> Dict[str, str]:
        """Get authorization headers for HTTP requests."""
        auth_data = {
            "id": auth_event.id,
            "pubkey": auth_event.public_key,
            "created_at": auth_event.created_at,
            "kind": auth_event.kind,
            "tags": auth_event.tags,
            "content": auth_event.content,
            "sig": auth_event.signature
        }
        
        return {
            "Authorization": f"Nostr {json.dumps(auth_data, separators=(',', ':'))}"
        }
    
    async def check_upload(self, blob: bytes, content_type: str) -> bool:
        """Check if upload would be accepted using HEAD /upload (BUD-06)."""
        sha256_hash = self._calculate_sha256(blob)
        
        headers = {
            "X-SHA-256": sha256_hash,
            "X-Content-Type": content_type,
            "X-Content-Length": str(len(blob))
        }
        
        try:
            response = await self.client.head(
                f"{self.base_url}/upload",
                headers=headers
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Upload check failed: {e}")
            return False
    
    async def upload_blob(self, blob: bytes, content_type: str) -> BlobDescriptor:
        """Upload a blob to the server (BUD-01)."""
        sha256_hash = self._calculate_sha256(blob)
        
        # Create auth event for upload
        auth_event = self._create_auth_event("upload", sha256_hash)
        headers = self._get_auth_headers(auth_event)
        headers["Content-Type"] = content_type
        
        try:
            response = await self.client.put(
                f"{self.base_url}/upload",
                content=blob,
                headers=headers
            )
            response.raise_for_status()
            
            blob_data = response.json()
            return BlobDescriptor(**blob_data)
            
        except Exception as e:
            logger.error(f"Upload failed: {e}")
            raise
    
    async def get_blob(self, sha256_hash: str, extension: Optional[str] = None) -> bytes:
        """Retrieve a blob by its SHA-256 hash (BUD-01)."""
        url_path = sha256_hash
        if extension:
            url_path += f".{extension}"
            
        try:
            response = await self.client.get(f"{self.base_url}/{url_path}")
            response.raise_for_status()
            return response.content
            
        except Exception as e:
            logger.error(f"Get blob failed: {e}")
            raise
    
    async def list_blobs(self, pubkey: Optional[str] = None) -> List[BlobDescriptor]:
        """List blobs for a public key (BUD-02)."""
        target_pubkey = pubkey or self.get_pubkey()
        
        # Create auth event for listing
        auth_event = self._create_auth_event("list")
        headers = self._get_auth_headers(auth_event)
        
        try:
            response = await self.client.get(
                f"{self.base_url}/list/{target_pubkey}",
                headers=headers
            )
            response.raise_for_status()
            
            blob_list = response.json()
            return [BlobDescriptor(**blob) for blob in blob_list]
            
        except Exception as e:
            logger.error(f"List blobs failed: {e}")
            raise
    
    async def delete_blob(self, sha256_hash: str) -> bool:
        """Delete a blob (BUD-01)."""
        # Create auth event for deletion
        auth_event = self._create_auth_event("delete", sha256_hash)
        headers = self._get_auth_headers(auth_event)
        
        try:
            response = await self.client.delete(
                f"{self.base_url}/{sha256_hash}",
                headers=headers
            )
            response.raise_for_status()
            return True
            
        except Exception as e:
            logger.error(f"Delete blob failed: {e}")
            return False
    
    async def mirror_blob(self, sha256_hash: str, target_server: str) -> bool:
        """Request server to mirror a blob from another server."""
        # Create auth event for mirroring
        auth_event = self._create_auth_event("mirror", sha256_hash)
        headers = self._get_auth_headers(auth_event)
        
        mirror_data = {
            "url": f"{target_server}/{sha256_hash}"
        }
        
        try:
            response = await self.client.put(
                f"{self.base_url}/mirror",
                json=mirror_data,
                headers=headers
            )
            response.raise_for_status()
            return True
            
        except Exception as e:
            logger.error(f"Mirror blob failed: {e}")
            return False
    
    async def optimize_media(self, sha256_hash: str) -> bytes:
        """Request optimized version of media (BUD-05)."""
        # Create auth event for media optimization
        auth_event = self._create_auth_event("media", sha256_hash)
        headers = self._get_auth_headers(auth_event)
        
        try:
            response = await self.client.put(
                f"{self.base_url}/media",
                headers=headers
            )
            response.raise_for_status()
            return response.content
            
        except Exception as e:
            logger.error(f"Media optimization failed: {e}")
            raise
    
    async def report_blob(self, sha256_hash: str, reason: str) -> bool:
        """Report a blob for abuse (BUD-09)."""
        # Create NIP-56 report event
        report_event = Event(
            kind=REPORT_KIND,
            content=reason,
            tags=[
                ["x", sha256_hash, "nudity"],  # Example type, should be based on reason
                ["L", "content-warning"],
                ["l", "nsfw", "content-warning"]
            ],
            created_at=int(time.time())
        )
        report_event.sign(self.private_key.hex())
        
        report_data = {
            "id": report_event.id,
            "pubkey": report_event.public_key,
            "created_at": report_event.created_at,
            "kind": report_event.kind,
            "tags": report_event.tags,
            "content": report_event.content,
            "sig": report_event.signature
        }
        
        try:
            response = await self.client.put(
                f"{self.base_url}/report",
                json=report_data
            )
            response.raise_for_status()
            return True
            
        except Exception as e:
            logger.error(f"Report blob failed: {e}")
            return False
    
    async def close(self):
        """Close the HTTP client."""
        await self.client.aclose()


class BlossomMCPServer:
    """MCP Server implementation for Blossom protocol."""
    
    def __init__(self):
        self.server = Server("blossom-mcp")
        self.blossom_client: Optional[BlossomServer] = None
        self.relay_manager: Optional[RelayManager] = None
        
        # Register handlers
        self.server.list_tools = self.list_tools
        self.server.call_tool = self.call_tool
        self.server.list_prompts = self.list_prompts
        self.server.get_prompt = self.get_prompt
    
    async def list_tools(self) -> ListToolsResult:
        """List available Blossom tools."""
        return ListToolsResult(
            tools=[
                Tool(
                    name="upload_blob",
                    description="Upload a blob to a Blossom server",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "server_url": {"type": "string", "description": "Blossom server URL"},
                            "blob_data": {"type": "string", "description": "Base64 encoded blob data"},
                            "content_type": {"type": "string", "description": "MIME type of the blob"},
                            "private_key": {"type": "string", "description": "Optional private key in hex"}
                        },
                        "required": ["server_url", "blob_data", "content_type"]
                    }
                ),
                Tool(
                    name="check_upload",
                    description="Check if a blob upload would be accepted",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "server_url": {"type": "string", "description": "Blossom server URL"},
                            "blob_data": {"type": "string", "description": "Base64 encoded blob data"},
                            "content_type": {"type": "string", "description": "MIME type of the blob"}
                        },
                        "required": ["server_url", "blob_data", "content_type"]
                    }
                ),
                Tool(
                    name="get_blob",
                    description="Retrieve a blob by its SHA-256 hash",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "server_url": {"type": "string", "description": "Blossom server URL"},
                            "sha256_hash": {"type": "string", "description": "SHA-256 hash of the blob"},
                            "extension": {"type": "string", "description": "Optional file extension"}
                        },
                        "required": ["server_url", "sha256_hash"]
                    }
                ),
                Tool(
                    name="list_blobs",
                    description="List blobs for a public key",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "server_url": {"type": "string", "description": "Blossom server URL"},
                            "pubkey": {"type": "string", "description": "Public key to list blobs for"},
                            "private_key": {"type": "string", "description": "Private key for authentication"}
                        },
                        "required": ["server_url"]
                    }
                ),
                Tool(
                    name="delete_blob",
                    description="Delete a blob from the server",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "server_url": {"type": "string", "description": "Blossom server URL"},
                            "sha256_hash": {"type": "string", "description": "SHA-256 hash of the blob to delete"},
                            "private_key": {"type": "string", "description": "Private key for authentication"}
                        },
                        "required": ["server_url", "sha256_hash", "private_key"]
                    }
                ),
                Tool(
                    name="mirror_blob",
                    description="Request server to mirror a blob from another server",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "server_url": {"type": "string", "description": "Target Blossom server URL"},
                            "sha256_hash": {"type": "string", "description": "SHA-256 hash of the blob"},
                            "source_server": {"type": "string", "description": "Source server URL"},
                            "private_key": {"type": "string", "description": "Private key for authentication"}
                        },
                        "required": ["server_url", "sha256_hash", "source_server", "private_key"]
                    }
                ),
                Tool(
                    name="optimize_media",
                    description="Request optimized version of media",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "server_url": {"type": "string", "description": "Blossom server URL"},
                            "sha256_hash": {"type": "string", "description": "SHA-256 hash of the media"},
                            "private_key": {"type": "string", "description": "Private key for authentication"}
                        },
                        "required": ["server_url", "sha256_hash", "private_key"]
                    }
                ),
                Tool(
                    name="report_blob",
                    description="Report a blob for abuse",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "server_url": {"type": "string", "description": "Blossom server URL"},
                            "sha256_hash": {"type": "string", "description": "SHA-256 hash of the blob to report"},
                            "reason": {"type": "string", "description": "Reason for reporting"},
                            "private_key": {"type": "string", "description": "Private key for authentication"}
                        },
                        "required": ["server_url", "sha256_hash", "reason", "private_key"]
                    }
                ),
                Tool(
                    name="get_pubkey",
                    description="Get public key from private key",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "private_key": {"type": "string", "description": "Private key in hex format"}
                        },
                        "required": ["private_key"]
                    }
                ),
                Tool(
                    name="generate_keypair",
                    description="Generate a new Nostr keypair",
                    inputSchema={
                        "type": "object",
                        "properties": {},
                        "required": []
                    }
                )
            ]
        )
    
    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> CallToolResult:
        """Handle tool calls."""
        try:
            if name == "upload_blob":
                return await self._upload_blob(arguments)
            elif name == "check_upload":
                return await self._check_upload(arguments)
            elif name == "get_blob":
                return await self._get_blob(arguments)
            elif name == "list_blobs":
                return await self._list_blobs(arguments)
            elif name == "delete_blob":
                return await self._delete_blob(arguments)
            elif name == "mirror_blob":
                return await self._mirror_blob(arguments)
            elif name == "optimize_media":
                return await self._optimize_media(arguments)
            elif name == "report_blob":
                return await self._report_blob(arguments)
            elif name == "get_pubkey":
                return await self._get_pubkey(arguments)
            elif name == "generate_keypair":
                return await self._generate_keypair(arguments)
            else:
                return CallToolResult(
                    content=[TextContent(type="text", text=f"Unknown tool: {name}")]
                )
        except Exception as e:
            logger.error(f"Tool call failed: {e}")
            return CallToolResult(
                content=[TextContent(type="text", text=f"Error: {str(e)}")]
            )
    
    async def _upload_blob(self, args: Dict[str, Any]) -> CallToolResult:
        """Handle blob upload."""
        import base64
        
        server_url = args["server_url"]
        blob_data = base64.b64decode(args["blob_data"])
        content_type = args["content_type"]
        private_key_hex = args.get("private_key")
        
        private_key = PrivateKey(bytes.fromhex(private_key_hex)) if private_key_hex else None
        client = BlossomServer(server_url, private_key)
        
        try:
            descriptor = await client.upload_blob(blob_data, content_type)
            result = {
                "success": True,
                "blob_descriptor": descriptor.dict(),
                "sha256": descriptor.sha256,
                "url": descriptor.url,
                "size": descriptor.size
            }
            return CallToolResult(
                content=[TextContent(type="text", text=json.dumps(result, indent=2))]
            )
        finally:
            await client.close()
    
    async def _check_upload(self, args: Dict[str, Any]) -> CallToolResult:
        """Handle upload check."""
        import base64
        
        server_url = args["server_url"]
        blob_data = base64.b64decode(args["blob_data"])
        content_type = args["content_type"]
        
        client = BlossomServer(server_url)
        
        try:
            accepted = await client.check_upload(blob_data, content_type)
            result = {
                "upload_accepted": accepted,
                "sha256": hashlib.sha256(blob_data).hexdigest(),
                "size": len(blob_data),
                "content_type": content_type
            }
            return CallToolResult(
                content=[TextContent(type="text", text=json.dumps(result, indent=2))]
            )
        finally:
            await client.close()
    
    async def _get_blob(self, args: Dict[str, Any]) -> CallToolResult:
        """Handle blob retrieval."""
        import base64
        
        server_url = args["server_url"]
        sha256_hash = args["sha256_hash"]
        extension = args.get("extension")
        
        client = BlossomServer(server_url)
        
        try:
            blob_data = await client.get_blob(sha256_hash, extension)
            result = {
                "success": True,
                "sha256": sha256_hash,
                "size": len(blob_data),
                "data": base64.b64encode(blob_data).decode('utf-8')
            }
            return CallToolResult(
                content=[TextContent(type="text", text=json.dumps(result, indent=2))]
            )
        finally:
            await client.close()
    
    async def _list_blobs(self, args: Dict[str, Any]) -> CallToolResult:
        """Handle blob listing."""
        server_url = args["server_url"]
        pubkey = args.get("pubkey")
        private_key_hex = args.get("private_key")
        
        private_key = PrivateKey(bytes.fromhex(private_key_hex)) if private_key_hex else None
        client = BlossomServer(server_url, private_key)
        
        try:
            descriptors = await client.list_blobs(pubkey)
            result = {
                "success": True,
                "pubkey": pubkey or client.get_pubkey(),
                "count": len(descriptors),
                "blobs": [desc.dict() for desc in descriptors]
            }
            return CallToolResult(
                content=[TextContent(type="text", text=json.dumps(result, indent=2))]
            )
        finally:
            await client.close()
    
    async def _delete_blob(self, args: Dict[str, Any]) -> CallToolResult:
        """Handle blob deletion."""
        server_url = args["server_url"]
        sha256_hash = args["sha256_hash"]
        private_key_hex = args["private_key"]
        
        private_key = PrivateKey(bytes.fromhex(private_key_hex))
        client = BlossomServer(server_url, private_key)
        
        try:
            success = await client.delete_blob(sha256_hash)
            result = {
                "success": success,
                "sha256": sha256_hash,
                "message": "Blob deleted successfully" if success else "Deletion failed"
            }
            return CallToolResult(
                content=[TextContent(type="text", text=json.dumps(result, indent=2))]
            )
        finally:
            await client.close()
    
    async def _mirror_blob(self, args: Dict[str, Any]) -> CallToolResult:
        """Handle blob mirroring."""
        server_url = args["server_url"]
        sha256_hash = args["sha256_hash"]
        source_server = args["source_server"]
        private_key_hex = args["private_key"]
        
        private_key = PrivateKey(bytes.fromhex(private_key_hex))
        client = BlossomServer(server_url, private_key)
        
        try:
            success = await client.mirror_blob(sha256_hash, source_server)
            result = {
                "success": success,
                "sha256": sha256_hash,
                "source_server": source_server,
                "target_server": server_url,
                "message": "Mirror request sent successfully" if success else "Mirror request failed"
            }
            return CallToolResult(
                content=[TextContent(type="text", text=json.dumps(result, indent=2))]
            )
        finally:
            await client.close()
    
    async def _optimize_media(self, args: Dict[str, Any]) -> CallToolResult:
        """Handle media optimization."""
        import base64
        
        server_url = args["server_url"]
        sha256_hash = args["sha256_hash"]
        private_key_hex = args["private_key"]
        
        private_key = PrivateKey(bytes.fromhex(private_key_hex))
        client = BlossomServer(server_url, private_key)
        
        try:
            optimized_data = await client.optimize_media(sha256_hash)
            result = {
                "success": True,
                "original_sha256": sha256_hash,
                "optimized_size": len(optimized_data),
                "optimized_data": base64.b64encode(optimized_data).decode('utf-8')
            }
            return CallToolResult(
                content=[TextContent(type="text", text=json.dumps(result, indent=2))]
            )
        finally:
            await client.close()
    
    async def _report_blob(self, args: Dict[str, Any]) -> CallToolResult:
        """Handle blob reporting."""
        server_url = args["server_url"]
        sha256_hash = args["sha256_hash"]
        reason = args["reason"]
        private_key_hex = args["private_key"]
        
        private_key = PrivateKey(bytes.fromhex(private_key_hex))
        client = BlossomServer(server_url, private_key)
        
        try:
            success = await client.report_blob(sha256_hash, reason)
            result = {
                "success": success,
                "sha256": sha256_hash,
                "reason": reason,
                "message": "Report submitted successfully" if success else "Report submission failed"
            }
            return CallToolResult(
                content=[TextContent(type="text", text=json.dumps(result, indent=2))]
            )
        finally:
            await client.close()
    
    async def _get_pubkey(self, args: Dict[str, Any]) -> CallToolResult:
        """Get public key from private key."""
        private_key_hex = args["private_key"]
        private_key = PrivateKey(bytes.fromhex(private_key_hex))
        
        result = {
            "private_key": private_key_hex,
            "public_key": private_key.public_key.hex(),
            "npub": private_key.public_key.bech32(),
            "nsec": private_key.bech32()
        }
        
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(result, indent=2))]
        )
    
    async def _generate_keypair(self, args: Dict[str, Any]) -> CallToolResult:
        """Generate a new keypair."""
        private_key = PrivateKey()
        
        result = {
            "private_key": private_key.hex(),
            "public_key": private_key.public_key.hex(),
            "npub": private_key.public_key.bech32(),
            "nsec": private_key.bech32()
        }
        
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(result, indent=2))]
        )
    
    async def list_prompts(self) -> ListPromptsResult:
        """List available prompts."""
        return ListPromptsResult(
            prompts=[
                Prompt(
                    name="blossom_usage_guide",
                    description="Guide for using the Blossom protocol MCP server"
                ),
                Prompt(
                    name="blossom_server_setup",
                    description="Instructions for setting up a Blossom server"
                )
            ]
        )
    
    async def get_prompt(self, name: str, arguments: Dict[str, str] | None = None) -> GetPromptResult:
        """Get a specific prompt."""
        if name == "blossom_usage_guide":
            content = """
# Blossom Protocol MCP Server Usage Guide

This MCP server provides tools for interacting with Blossom protocol servers, which offer decentralized blob storage using Nostr-based authentication.

## Key Concepts

- **Blobs**: Binary data stored on servers, identified by SHA-256 hash
- **Authorization**: Uses Nostr events (kind 24242) for authentication
- **Servers**: HTTP endpoints that implement the Blossom protocol

## Common Workflows

### 1. Upload a file
```
1. Generate or use existing keypair
2. Encode file as base64
3. Use upload_blob tool with server URL, blob data, and content type
```

### 2. Retrieve a file
```
1. Use get_blob tool with server URL and SHA-256 hash
2. Decode returned base64 data
```

### 3. Manage your files
```
1. Use list_blobs to see your uploaded files
2. Use delete_blob to remove files you own
```

## Security Notes

- Private keys are required for upload, delete, and list operations
- Keep your private keys secure
- Servers may have size limits and content policies
- Use check_upload to verify acceptance before uploading
"""
            
            return GetPromptResult(
                description="Comprehensive guide for using the Blossom MCP server",
                messages=[
                    {
                        "role": "user",
                        "content": {
                            "type": "text",
                            "text": content
                        }
                    }
                ]
            )
        
        elif name == "blossom_server_setup":
            content = """
# Blossom Server Setup Guide

## Popular Blossom Servers

- `https://blossom.nostrmedia.com` - Community server
- `https://media.nostrgarden.com` - Garden-themed server
- `https://files.sovbit.host` - Sovereign Bitcoin hosting

## Testing Your Setup

1. Generate a keypair:
   ```json
   {
     "tool": "generate_keypair",
     "arguments": {}
   }
   ```

2. Test upload capability:
   ```json
   {
     "tool": "check_upload",
     "arguments": {
       "server_url": "https://blossom.nostrmedia.com",
       "blob_data": "SGVsbG8gV29ybGQ=",
       "content_type": "text/plain"
     }
   }
   ```

## BUD Specifications Implemented

- **BUD-01**: Basic blob operations (upload, download, delete)
- **BUD-02**: Blob listing by public key
- **BUD-05**: Media optimization
- **BUD-06**: Upload pre-validation
- **BUD-09**: Content reporting

## Error Handling

The server handles common errors:
- Authentication failures
- Network timeouts
- Invalid blob hashes
- Server capacity limits
"""
            
            return GetPromptResult(
                description="Instructions for setting up and testing Blossom servers",
                messages=[
                    {
                        "role": "user",
                        "content": {
                            "type": "text",
                            "text": content
                        }
                    }
                ]
            )
        
        else:
            return GetPromptResult(
                description="Unknown prompt",
                messages=[
                    {
                        "role": "user",
                        "content": {
                            "type": "text",
                            "text": f"Unknown prompt: {name}"
                        }
                    }
                ]
            )


async def main():
    """Main entry point for the MCP server."""
    mcp_server = BlossomMCPServer()
    
    # Setup transport
    options = InitializationOptions(
        server_name="blossom-mcp",
        server_version="1.0.0",
        capabilities=mcp_server.server.get_capabilities(
            notification_options=None,
            experimental_capabilities=None,
        ),
    )
    
    async with stdio_server() as (read_stream, write_stream):
        await mcp_server.server.run(
            read_stream,
            write_stream,
            options,
        )


if __name__ == "__main__":
    import sys
    
    # Add error handling for missing dependencies
    try:
        import httpx
    except ImportError as e:
        print(f"Missing required dependency: {e}", file=sys.stderr)
        print("Please install required packages:", file=sys.stderr)
        print("pip install python-nostr httpx mcp", file=sys.stderr)
        sys.exit(1)
    
    asyncio.run(main())