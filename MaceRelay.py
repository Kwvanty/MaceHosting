"""Mace Social Worlds TCP relay over authenticated WebSocket agents.

Run on a public VPS, preferably behind Caddy/Nginx TLS:
    MACE_RELAY_SECRET=<same-secret-as-MaceHost> python MaceRelay.py

Only authorized launcher agents connect to this service. Minecraft TCP is
forwarded between a host-side agent and friend-side agent; it is never exposed
as an unauthenticated public TCP port. Tickets are signed by MaceHost.
"""
from __future__ import annotations

import asyncio
import hmac
import json
import logging
from http import HTTPStatus
import os
import ssl
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import websockets
from websockets.datastructures import Headers
from websockets.exceptions import ConnectionClosed
from websockets.http11 import Response

LOG = logging.getLogger("MaceRelay")
MAX_FRAME_BYTES = 1024 * 1024
MAX_DATA_CHUNK = 48 * 1024
STREAM_ID_BYTES = 16


def _b64url_decode(value: str) -> bytes:
    import base64
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def verify_ticket(ticket: str, secret: str) -> dict[str, Any]:
    """Verify the same HMAC ticket format issued by MaceHost."""
    if not isinstance(ticket, str) or len(ticket) > 4096 or "." not in ticket:
        raise ValueError("invalid ticket format")
    payload_part, signature = ticket.split(".", 1)
    expected = hmac.new(secret.encode("utf-8"), payload_part.encode("ascii"), "sha256").hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise ValueError("invalid ticket signature")
    payload = json.loads(_b64url_decode(payload_part).decode("utf-8"))
    if not isinstance(payload, dict) or payload.get("v") != 1:
        raise ValueError("unsupported ticket")
    if int(payload.get("exp", 0)) <= int(time.time()):
        raise ValueError("ticket expired")
    if not isinstance(payload.get("sid"), str) or len(payload["sid"]) != 32:
        raise ValueError("invalid session id")
    if payload.get("role") not in {"host", "join"}:
        raise ValueError("invalid role")
    if int(payload.get("uid", 0)) <= 0:
        raise ValueError("invalid user id")
    return payload


@dataclass
class Connection:
    connection_id: str
    session_id: str
    user_id: int
    role: str
    expires_at: int
    websocket: Any
    send_lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def send(self, message: str | bytes) -> None:
        async with self.send_lock:
            await self.websocket.send(message)


@dataclass
class StreamRoute:
    stream_id: str
    host_connection_id: str
    join_connection_id: str
    created_at: float = field(default_factory=time.monotonic)


class MaceRelay:
    def __init__(self, secret: str):
        self.secret = secret
        self.connections: dict[str, Connection] = {}
        self.hosts: dict[str, str] = {}  # session_id -> connection_id
        self.joiners: dict[tuple[str, int], str] = {}  # (session_id, user_id) -> connection_id
        self.routes: dict[str, StreamRoute] = {}
        self.state_lock = asyncio.Lock()
        self.started_at = time.time()

    async def _send_json(self, connection_id: str, data: dict[str, Any]) -> bool:
        connection = self.connections.get(connection_id)
        if not connection:
            return False
        try:
            await connection.send(json.dumps(data, separators=(",", ":")))
            return True
        except ConnectionClosed:
            return False
        except Exception:
            LOG.exception("WebSocket message send failed")
            return False

    async def handler(self, websocket):
        connection_id = uuid.uuid4().hex
        connection = None
        expiry_task = None
        try:
            try:
                raw = await asyncio.wait_for(websocket.recv(), timeout=10)
            except asyncio.TimeoutError:
                await websocket.close(code=4401, reason="authentication timeout")
                return
            if not isinstance(raw, str) or len(raw) > 8192:
                await websocket.close(code=4401, reason="authentication required")
                return
            try:
                auth = json.loads(raw)
                if auth.get("type") != "auth":
                    raise ValueError("authentication required")
                claims = verify_ticket(str(auth.get("ticket") or ""), self.secret)
            except Exception as exc:
                await websocket.close(code=4401, reason="invalid or expired ticket")
                LOG.warning("Rejected WebSocket authentication: %s", exc)
                return

            session_id = str(claims["sid"])
            user_id = int(claims["uid"])
            role = str(claims["role"])
            connection = Connection(connection_id, session_id, user_id, role, int(claims["exp"]), websocket)
            async with self.state_lock:
                if role == "host":
                    old_id = self.hosts.get(session_id)
                    if old_id and old_id in self.connections:
                        await websocket.close(code=4409, reason="host already connected")
                        return
                    self.hosts[session_id] = connection_id
                else:
                    peer_key = (session_id, user_id)
                    old_id = self.joiners.get(peer_key)
                    if old_id and old_id in self.connections:
                        await websocket.close(code=4409, reason="this player is already connected")
                        return
                    self.joiners[peer_key] = connection_id
                self.connections[connection_id] = connection
            host_id = self.hosts.get(session_id)
            await connection.send(json.dumps({
                "type": "auth_ok", "session_id": session_id, "role": role,
                "host_online": bool(host_id and host_id in self.connections),
                "server_time": int(time.time()),
            }, separators=(",", ":")))
            LOG.info("Agent joined: session=%s role=%s user=%s", session_id[:8], role, user_id)
            expiry_task = asyncio.create_task(self._expire_connection(connection))

            async for message in websocket:
                if isinstance(message, bytes):
                    await self._route_data(connection, message)
                else:
                    if len(message) > 8192:
                        await websocket.close(code=4400, reason="control message too large")
                        break
                    try:
                        packet = json.loads(message)
                    except (ValueError, TypeError):
                        await websocket.close(code=4400, reason="invalid control message")
                        break
                    await self._route_control(connection, packet)
        except ConnectionClosed:
            pass
        except asyncio.CancelledError:
            raise
        except Exception:
            LOG.exception("Agent handler error")
        finally:
            if expiry_task is not None:
                expiry_task.cancel()
                await asyncio.gather(expiry_task, return_exceptions=True)
            if connection is not None:
                await self._disconnect(connection)

    async def _expire_connection(self, connection: Connection) -> None:
        delay = max(0.0, float(connection.expires_at) - time.time())
        await asyncio.sleep(delay)
        try:
            await connection.websocket.close(code=4401, reason="ticket expired; reconnect with a fresh ticket")
        except Exception:
            pass

    async def _route_control(self, sender: Connection, packet: dict[str, Any]) -> None:
        kind = str(packet.get("type") or "")
        if kind == "ping":
            await self._send_json(sender.connection_id, {"type": "pong", "time": int(time.time())})
            return
        stream_id = str(packet.get("stream_id") or "")
        if len(stream_id) != 32:
            return
        try:
            int(stream_id, 16)
        except ValueError:
            return

        if kind == "open":
            if sender.role != "join":
                return
            host_id = self.hosts.get(sender.session_id)
            host = self.connections.get(host_id or "")
            if not host or host.role != "host":
                await self._send_json(sender.connection_id, {"type": "open_result", "stream_id": stream_id, "ok": False, "error": "Владелец мира сейчас не подключён."})
                return
            async with self.state_lock:
                if stream_id in self.routes or len(self.routes) >= 512:
                    await self._send_json(sender.connection_id, {"type": "open_result", "stream_id": stream_id, "ok": False, "error": "Лимит сетевых потоков достигнут."})
                    return
                self.routes[stream_id] = StreamRoute(stream_id, host.connection_id, sender.connection_id)
            ok = await self._send_json(host.connection_id, {"type": "open", "stream_id": stream_id})
            if not ok:
                self.routes.pop(stream_id, None)
                await self._send_json(sender.connection_id, {"type": "open_result", "stream_id": stream_id, "ok": False, "error": "Туннель владельца недоступен."})
            return

        route = self.routes.get(stream_id)
        if not route:
            return
        if kind == "open_result" and sender.role == "host" and sender.connection_id == route.host_connection_id:
            target_id = route.join_connection_id
            ok = bool(packet.get("ok"))
            await self._send_json(target_id, {
                "type": "open_result", "stream_id": stream_id, "ok": ok,
                "error": str(packet.get("error") or "")[:240],
            })
            if not ok:
                self.routes.pop(stream_id, None)
            return

        if kind == "close":
            if sender.connection_id == route.host_connection_id:
                target_id = route.join_connection_id
            elif sender.connection_id == route.join_connection_id:
                target_id = route.host_connection_id
            else:
                return
            self.routes.pop(stream_id, None)
            await self._send_json(target_id, {"type": "close", "stream_id": stream_id, "reason": str(packet.get("reason") or "closed")[:120]})

    async def _route_data(self, sender: Connection, message: bytes) -> None:
        if len(message) <= STREAM_ID_BYTES or len(message) > MAX_DATA_CHUNK + STREAM_ID_BYTES:
            return
        stream_id = message[:STREAM_ID_BYTES].hex()
        route = self.routes.get(stream_id)
        if not route:
            return
        if sender.connection_id == route.host_connection_id:
            target_id = route.join_connection_id
        elif sender.connection_id == route.join_connection_id:
            target_id = route.host_connection_id
        else:
            return
        target = self.connections.get(target_id)
        if not target:
            self.routes.pop(stream_id, None)
            return
        try:
            await target.send(message)
        except ConnectionClosed:
            self.routes.pop(stream_id, None)

    async def _disconnect(self, connection: Connection) -> None:
        async with self.state_lock:
            self.connections.pop(connection.connection_id, None)
            if self.hosts.get(connection.session_id) == connection.connection_id:
                self.hosts.pop(connection.session_id, None)
            peer_key = (connection.session_id, connection.user_id)
            if self.joiners.get(peer_key) == connection.connection_id:
                self.joiners.pop(peer_key, None)
            affected = [route for route in self.routes.values()
                        if connection.connection_id in (route.host_connection_id, route.join_connection_id)]
            for route in affected:
                self.routes.pop(route.stream_id, None)
        for route in affected:
            other = route.join_connection_id if connection.connection_id == route.host_connection_id else route.host_connection_id
            await self._send_json(other, {"type": "close", "stream_id": route.stream_id, "reason": "agent_disconnected"})
        LOG.info("Agent left: session=%s role=%s user=%s", connection.session_id[:8], connection.role, connection.user_id)

    async def health(self) -> dict[str, Any]:
        return {
            "ok": True,
            "service": "MaceRelay",
            "uptime_seconds": int(time.time() - self.started_at),
            "connected_agents": len(self.connections),
            "active_streams": len(self.routes),
            "active_sessions": len(self.hosts),
        }


async def main() -> None:
    logging.basicConfig(level=os.getenv("MACE_RELAY_LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    secret = os.getenv("MACE_RELAY_SECRET", "").strip()
    if len(secret) < 32:
        raise SystemExit("Set MACE_RELAY_SECRET to a random secret of at least 32 characters (same value as MaceHost).")
    host = os.getenv("MACE_RELAY_BIND_HOST", "127.0.0.1").strip()
    port = int(os.getenv("MACE_RELAY_PORT", "8765"))
    tls_cert = os.getenv("MACE_RELAY_TLS_CERT", "").strip()
    tls_key = os.getenv("MACE_RELAY_TLS_KEY", "").strip()
    tls_context = None
    if tls_cert or tls_key:
        if not (tls_cert and tls_key):
            raise SystemExit("Set both MACE_RELAY_TLS_CERT and MACE_RELAY_TLS_KEY, or neither.")
        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
        tls_context.load_cert_chain(tls_cert, tls_key)
    elif host not in {"127.0.0.1", "localhost", "::1"}:
        raise SystemExit("Refusing plaintext relay on a public bind address. Use TLS or bind to loopback behind a TLS reverse proxy.")
    relay = MaceRelay(secret)

    async def process_request(connection, request):
        if request.path.split("?", 1)[0] == "/healthz":
            payload = json.dumps(await relay.health(), separators=(",", ":")).encode("utf-8")
            headers = Headers([
                ("Content-Type", "application/json; charset=utf-8"),
                ("Cache-Control", "no-store"),
                ("Content-Length", str(len(payload))),
            ])
            return Response(HTTPStatus.OK, "OK", headers, payload)
        return None

    async with websockets.serve(
        relay.handler, host, port, ssl=tls_context, process_request=process_request,
        max_size=MAX_FRAME_BYTES, max_queue=32,
        ping_interval=20, ping_timeout=20, close_timeout=5,
        compression=None,
    ):
        LOG.info("MaceRelay listening on %s:%s (tls=%s)", host, port, bool(tls_context))
        await asyncio.Future()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
