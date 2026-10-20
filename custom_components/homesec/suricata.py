"""Async TCP listener for Suricata EVE JSON alert entries.

The companion ``suricata_pusher.py`` script (run on the Suricata host) tails
eve-alert.json and streams each new line over a persistent TCP connection to
this listener.  Only entries with ``event_type == "alert"`` are ingested; all
others are silently discarded so the log stays focused on actionable events.

Every field coming off the wire is untrusted: it is type-coerced and
length-capped in :func:`sanitize_alert` before it is stored, rendered by the
panel, or fired as a Home Assistant event.

Optional hardening (configured from the Settings page):

* ``auth_token`` — when set, the first line a client sends must be
  ``AUTH <token>``; the connection is closed otherwise.
* ``allowed_networks`` — when non-empty, connections from any other source
  address are closed immediately.
"""

from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import Callable
from datetime import UTC, datetime
import hmac
import ipaddress
import json
import logging
from typing import Any

_LOGGER = logging.getLogger(__name__)

# Hard ceiling on a single incoming line to prevent memory exhaustion
_MAX_LINE_BYTES = 64 * 1024  # 64 KB
# Seconds a client has to authenticate before it is dropped
_AUTH_TIMEOUT_SECONDS = 10.0
# Idle connections are closed after this many seconds without data
_IDLE_TIMEOUT_SECONDS = 120.0
# Maximum simultaneous pusher connections
MAX_CONNECTIONS = 16
# Maximum distinct exporter addresses remembered for statistics
MAX_TRACKED_EXPORTERS = 32

# Per-field length caps for strings stored from an alert
_STR_LIMITS: dict[str, int] = {
    "src_ip": 64,
    "dest_ip": 64,
    "proto": 16,
    "app_proto": 32,
    "signature": 512,
    "category": 256,
    "action": 16,
    "in_iface": 64,
    "event_timestamp": 64,
}


def _clean_str(value: Any, limit: int) -> str:
    if value is None:
        return ""
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        return ""
    return str(value)[:limit]


def _clean_int(value: Any, low: int, high: int) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        number = value
    elif isinstance(value, str) and value.strip().lstrip("-").isdigit():
        number = int(value.strip())
    else:
        return None
    if number < low or number > high:
        return None
    return number


def _clean_ip(value: Any) -> str:
    text = _clean_str(value, _STR_LIMITS["src_ip"]).strip()
    if not text:
        return ""
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return ""


def sanitize_alert(entry: Any, received_at: datetime | None = None) -> dict[str, Any] | None:
    """Return a normalised alert record, or ``None`` if *entry* is not an alert.

    The stored ``timestamp`` is the time the listener received the alert, so a
    client cannot pin records in the log by sending a far-future timestamp.
    The sensor's own timestamp is kept (as text) in ``event_timestamp``.
    """
    if not isinstance(entry, dict) or entry.get("event_type") != "alert":
        return None
    alert = entry.get("alert")
    if not isinstance(alert, dict):
        alert = {}
    received_at = received_at or datetime.now(UTC)
    severity = _clean_int(alert.get("severity"), 1, 255)
    return {
        "timestamp": received_at.isoformat(),
        "event_timestamp": _clean_str(entry.get("timestamp"), _STR_LIMITS["event_timestamp"]),
        "src_ip": _clean_ip(entry.get("src_ip")),
        "src_port": _clean_int(entry.get("src_port"), 0, 65535),
        "dest_ip": _clean_ip(entry.get("dest_ip")),
        "dest_port": _clean_int(entry.get("dest_port"), 0, 65535),
        "proto": _clean_str(entry.get("proto"), _STR_LIMITS["proto"]),
        "app_proto": _clean_str(entry.get("app_proto"), _STR_LIMITS["app_proto"]),
        "signature": _clean_str(alert.get("signature"), _STR_LIMITS["signature"]),
        "signature_id": _clean_int(alert.get("signature_id"), 0, 2**32 - 1),
        "category": _clean_str(alert.get("category"), _STR_LIMITS["category"]),
        "severity": severity if severity is not None else 3,
        "action": _clean_str(alert.get("action"), _STR_LIMITS["action"]) or "allowed",
        "in_iface": _clean_str(entry.get("in_iface"), _STR_LIMITS["in_iface"]),
        "flow_id": _clean_int(entry.get("flow_id"), 0, 2**64 - 1),
    }


def sanitize_stored_record(record: Any) -> dict[str, Any] | None:
    """Re-validate a record loaded from storage (written by an older version).

    Records whose timestamp is missing, unparsable or in the future are dropped.
    """
    if not isinstance(record, dict):
        return None
    try:
        received_at = datetime.fromisoformat(str(record.get("timestamp")))
    except (TypeError, ValueError):
        return None
    if received_at.tzinfo is None:
        received_at = received_at.replace(tzinfo=UTC)
    if received_at > datetime.now(UTC):
        return None
    clean = sanitize_alert(
        {
            "event_type": "alert",
            "timestamp": record.get("event_timestamp") or record.get("timestamp"),
            "src_ip": record.get("src_ip"),
            "src_port": record.get("src_port"),
            "dest_ip": record.get("dest_ip"),
            "dest_port": record.get("dest_port"),
            "proto": record.get("proto"),
            "app_proto": record.get("app_proto"),
            "in_iface": record.get("in_iface"),
            "flow_id": record.get("flow_id"),
            "alert": {
                "signature": record.get("signature"),
                "signature_id": record.get("signature_id"),
                "category": record.get("category"),
                "severity": record.get("severity"),
                "action": record.get("action"),
            },
        },
        received_at=received_at,
    )
    return clean


def parse_allowed_networks(raw: str | None) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Parse a comma/newline separated list of IPs or CIDRs (raises ValueError)."""
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for token in str(raw or "").replace("\n", ",").split(","):
        token = token.strip()
        if token:
            networks.append(ipaddress.ip_network(token, strict=False))
    return networks


class SuricataAlertListener:
    """Async TCP server receiving newline-delimited EVE JSON from suricata_pusher."""

    def __init__(
        self,
        host: str,
        port: int,
        alert_log: deque,
        on_alert: Callable[[dict], None] | None = None,
        auth_token: str | None = None,
        allowed_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] | None = None,
    ) -> None:
        self._host = host
        self._port = port
        self._alert_log = alert_log
        self._on_alert = on_alert
        self._auth_token = (auth_token or "").strip()
        self._allowed_networks = list(allowed_networks or [])
        self._server: asyncio.AbstractServer | None = None
        self._total_received: int = 0
        self._rejected_connections: int = 0
        self._active_connections: int = 0
        self._started_at: datetime | None = None
        self._exporter_ips: list[str] = []

    async def async_start(self) -> None:
        """Bind the TCP server and start accepting connections."""
        self._server = await asyncio.start_server(
            self._handle_connection,
            self._host,
            self._port,
            reuse_address=True,
            limit=_MAX_LINE_BYTES,
        )
        self._started_at = datetime.now(UTC)
        addr = self._server.sockets[0].getsockname()
        _LOGGER.info(
            "HomeSec Suricata alert listener started on %s:%d", addr[0], addr[1]
        )
        if not self._auth_token and not self._allowed_networks:
            _LOGGER.warning(
                "HomeSec Suricata listener accepts alerts from any host without "
                "authentication. Set an auth token or an allowed-sources list in "
                "the Suricata settings."
            )

    async def async_stop(self) -> None:
        """Close the TCP server gracefully."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
            _LOGGER.info("HomeSec Suricata alert listener stopped")

    def _source_allowed(self, peer_ip: str) -> bool:
        if not self._allowed_networks:
            return True
        try:
            address = ipaddress.ip_address(peer_ip)
        except ValueError:
            return False
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        return any(address in network for network in self._allowed_networks)

    async def _authenticate(self, reader: asyncio.StreamReader) -> bool:
        if not self._auth_token:
            return True
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=_AUTH_TIMEOUT_SECONDS)
        except (TimeoutError, ValueError, asyncio.LimitOverrunError):
            return False
        text = line.decode("utf-8", errors="replace").strip()
        if not text.startswith("AUTH "):
            return False
        return hmac.compare_digest(text[5:].strip().encode(), self._auth_token.encode())

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle a single pusher connection; read newline-delimited JSON lines."""
        peer = writer.get_extra_info("peername") or ("unknown", 0)
        peer_ip = str(peer[0])
        if (
            self._active_connections >= MAX_CONNECTIONS
            or not self._source_allowed(peer_ip)
        ):
            self._rejected_connections += 1
            _LOGGER.debug("Suricata listener: rejected connection from %s", peer_ip)
            writer.close()
            return
        self._active_connections += 1
        try:
            if not await self._authenticate(reader):
                self._rejected_connections += 1
                _LOGGER.warning("Suricata listener: authentication failed from %s", peer_ip)
                return
            if (
                peer_ip != "unknown"
                and peer_ip not in self._exporter_ips
                and len(self._exporter_ips) < MAX_TRACKED_EXPORTERS
            ):
                self._exporter_ips.append(peer_ip)
            _LOGGER.debug("Suricata pusher connected from %s", peer_ip)
            while True:
                try:
                    line = await asyncio.wait_for(reader.readline(), timeout=_IDLE_TIMEOUT_SECONDS)
                except TimeoutError:
                    # No data for 2 min — close idle connection so it doesn't leak
                    break
                except (ValueError, asyncio.LimitOverrunError):
                    # Line longer than the stream limit: the stream position is
                    # undefined afterwards, so drop the connection.
                    _LOGGER.warning(
                        "Suricata listener: oversized line from %s, closing connection",
                        peer_ip,
                    )
                    break
                if not line:
                    break  # EOF: pusher closed gracefully

                try:
                    entry = json.loads(line.decode("utf-8", errors="replace").strip())
                except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
                    continue

                record = sanitize_alert(entry)
                if record is None:
                    continue
                self._alert_log.append(record)
                self._total_received += 1
                if self._on_alert is not None:
                    try:
                        self._on_alert(record)
                    except Exception:  # noqa: BLE001
                        _LOGGER.debug("Suricata on_alert callback failed", exc_info=True)

        except (ConnectionResetError, asyncio.IncompleteReadError):
            pass
        except Exception as exc:  # noqa: BLE001
            _LOGGER.debug("Suricata listener: unexpected error from %s: %s", peer_ip, exc)
        finally:
            self._active_connections -= 1
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass
            _LOGGER.debug("Suricata pusher disconnected from %s", peer_ip)

    def stats(self) -> dict[str, object]:
        """Return runtime statistics for the listener."""
        return {
            "running": self._server is not None,
            "host": self._host,
            "port": self._port,
            "total_received": self._total_received,
            "rejected_connections": self._rejected_connections,
            "active_connections": self._active_connections,
            "auth_required": bool(self._auth_token),
            "allowlist": bool(self._allowed_networks),
            "started_at": self._started_at.isoformat() if self._started_at else None,
            "exporter_ips": list(self._exporter_ips),
        }
