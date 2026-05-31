"""Async TCP listener for Suricata EVE JSON alert entries.

The companion ``suricata_pusher.py`` script (run on the Suricata host) tails
eve-alert.json and streams each new line over a persistent TCP connection to
this listener.  Only entries with ``event_type == "alert"`` are ingested; all
others are silently discarded so the log stays focused on actionable events.
"""

from __future__ import annotations

import asyncio
from collections import deque
from datetime import datetime, UTC
import json
import logging
from typing import Callable, Optional

_LOGGER = logging.getLogger(__name__)

# Hard ceiling on a single incoming line to prevent memory exhaustion
_MAX_LINE_BYTES = 64 * 1024  # 64 KB


class SuricataAlertListener:
    """Async TCP server receiving newline-delimited EVE JSON from suricata_pusher."""

    def __init__(
        self,
        host: str,
        port: int,
        alert_log: deque,
        on_alert: Callable[[dict], None] | None = None,
    ) -> None:
        self._host = host
        self._port = port
        self._alert_log = alert_log
        self._on_alert = on_alert
        self._server: asyncio.AbstractServer | None = None
        self._total_received: int = 0
        self._active_connections: int = 0
        self._started_at: Optional[datetime] = None
        self._exporter_ips: list[str] = []

    async def async_start(self) -> None:
        """Bind the TCP server and start accepting connections."""
        self._server = await asyncio.start_server(
            self._handle_connection,
            self._host,
            self._port,
            reuse_address=True,
        )
        self._started_at = datetime.now(UTC)
        addr = self._server.sockets[0].getsockname()
        _LOGGER.info(
            "HomeSec Suricata alert listener started on %s:%d", addr[0], addr[1]
        )

    async def async_stop(self) -> None:
        """Close the TCP server gracefully."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
            _LOGGER.info("HomeSec Suricata alert listener stopped")

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle a single pusher connection; read newline-delimited JSON lines."""
        peer = writer.get_extra_info("peername", ("unknown", 0))
        _LOGGER.debug("Suricata pusher connected from %s:%s", peer[0], peer[1])
        self._active_connections += 1
        peer_ip = str(peer[0])
        if peer_ip and peer_ip != "unknown" and peer_ip not in self._exporter_ips:
            self._exporter_ips.append(peer_ip)
        try:
            while True:
                try:
                    line = await asyncio.wait_for(reader.readline(), timeout=120.0)
                except asyncio.TimeoutError:
                    # No data for 2 min — close idle connection so it doesn't leak
                    break
                if not line:
                    break  # EOF: pusher closed gracefully

                if len(line) > _MAX_LINE_BYTES:
                    _LOGGER.warning(
                        "Suricata listener: oversized line from %s (%d bytes), discarding",
                        peer[0],
                        len(line),
                    )
                    continue

                try:
                    entry = json.loads(line.decode("utf-8", errors="replace").strip())
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue

                if not isinstance(entry, dict):
                    continue
                if entry.get("event_type") != "alert":
                    continue  # Only ingest alert events

                alert_sub = entry.get("alert") or {}
                record: dict = {
                    "timestamp": entry.get("timestamp", datetime.now(UTC).isoformat()),
                    "src_ip": str(entry.get("src_ip") or ""),
                    "src_port": entry.get("src_port"),
                    "dest_ip": str(entry.get("dest_ip") or ""),
                    "dest_port": entry.get("dest_port"),
                    "proto": str(entry.get("proto") or ""),
                    "app_proto": str(entry.get("app_proto") or ""),
                    "signature": str(alert_sub.get("signature") or ""),
                    "signature_id": alert_sub.get("signature_id"),
                    "category": str(alert_sub.get("category") or ""),
                    "severity": int(alert_sub.get("severity") or 3),
                    "action": str(alert_sub.get("action") or "allowed"),
                    "in_iface": str(entry.get("in_iface") or ""),
                    "flow_id": entry.get("flow_id"),
                }
                self._alert_log.append(record)
                self._total_received += 1
                if self._on_alert is not None:
                    try:
                        self._on_alert(record)
                    except Exception:  # noqa: BLE001
                        pass

        except (ConnectionResetError, asyncio.IncompleteReadError):
            pass
        except Exception as exc:  # noqa: BLE001
            _LOGGER.debug("Suricata listener: unexpected error from %s: %s", peer[0], exc)
        finally:
            self._active_connections -= 1
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass
            _LOGGER.debug("Suricata pusher disconnected from %s:%s", peer[0], peer[1])

    def stats(self) -> dict[str, object]:
        """Return runtime statistics for the listener."""
        return {
            "running": self._server is not None,
            "host": self._host,
            "port": self._port,
            "total_received": self._total_received,
            "active_connections": self._active_connections,
            "started_at": self._started_at.isoformat() if self._started_at else None,
            "exporter_ips": list(self._exporter_ips),
        }
