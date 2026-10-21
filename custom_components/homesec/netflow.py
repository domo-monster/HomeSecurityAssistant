from __future__ import annotations

import asyncio
from asyncio import DatagramProtocol
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
import ipaddress
import logging
import struct
from typing import Any

_LOGGER = logging.getLogger(__name__)

# Upper bound on templates kept per exporter.  Templates are keyed on values
# chosen by the sender (source id + template id), so without a cap a single
# host can exhaust memory by announcing endless distinct templates.
MAX_TEMPLATES_PER_EXPORTER = 256
# Upper bound on distinct exporter addresses remembered for statistics.
MAX_TRACKED_EXPORTERS = 64
# Datagrams buffered between two event-loop iterations before dropping
MAX_BUFFERED_DATAGRAMS = 5000


@dataclass(slots=True)
class TemplateField:
    field_type: int
    field_length: int


@dataclass(slots=True)
class ParserStats:
    total_datagrams: int = 0
    parsed_datagrams: int = 0
    dropped_datagrams: int = 0
    templates_registered: int = 0
    data_sets_without_template: int = 0
    templates_rejected: int = 0
    rejected_datagrams: int = 0
    last_error: str | None = None
    versions_seen: set[str] = field(default_factory=set)
    exporters: set[str] = field(default_factory=set)

    def as_dict(self, active_templates: int) -> dict[str, object]:
        return {
            "total_datagrams": self.total_datagrams,
            "parsed_datagrams": self.parsed_datagrams,
            "dropped_datagrams": self.dropped_datagrams,
            "templates_registered": self.templates_registered,
            "active_templates": active_templates,
            "data_sets_without_template": self.data_sets_without_template,
            "templates_rejected": self.templates_rejected,
            "rejected_datagrams": self.rejected_datagrams,
            "last_error": self.last_error,
            "versions_seen": sorted(self.versions_seen),
            "exporters": sorted(self.exporters),
        }


@dataclass(slots=True)
class FlowRecord:
    src_ip: ipaddress.IPv4Address | ipaddress.IPv6Address
    dst_ip: ipaddress.IPv4Address | ipaddress.IPv6Address
    src_port: int
    dst_port: int
    protocol: int
    packets: int
    octets: int
    timestamp: datetime
    tcp_flags: int


_INT_CODES = {1: "B", 2: "H", 4: "I", 8: "Q"}
# FlowRecord integer fields and their IPFIX / NetFlow v9 information element ids
_INT_FIELDS = (("src_port", 7), ("dst_port", 11), ("protocol", 4), ("packets", 2), ("octets", 1), ("tcp_flags", 6))


class _TemplateDecoder:
    """Decode records of one template with a single precompiled struct.

    Built once when the template is registered.  Semantics match a field
    dictionary: the last occurrence of an element wins, IPv4 addresses
    (8/12, 4 bytes) take precedence over IPv6 (27/28, 16 bytes), a record
    without either pair is skipped and missing integer fields are 0.
    """

    __slots__ = ("record_length", "_struct", "_names", "_from_bytes", "_v6", "skip")

    _struct: struct.Struct | None
    _names: tuple[str, ...]
    _from_bytes: tuple[bool, ...]

    def __init__(self, template: tuple[TemplateField, ...]) -> None:
        last: dict[int, tuple[int, int]] = {}
        offset = 0
        for template_field in template:
            last[template_field.field_type] = (offset, template_field.field_length)
            offset += template_field.field_length
        self.record_length = offset
        self._v6 = False
        if last.get(8, (0, 0))[1] == 4 and last.get(12, (0, 0))[1] == 4:
            wanted = [("src_ip", 8), ("dst_ip", 12)]
        elif last.get(27, (0, 0))[1] == 16 and last.get(28, (0, 0))[1] == 16:
            wanted = [("src_ip", 27), ("dst_ip", 28)]
            self._v6 = True
        else:
            # No usable address pair: every record of this template is skipped
            self.skip = True
            self._struct = None
            self._names = ()
            self._from_bytes = ()
            return
        self.skip = False
        wanted += [(name, element) for name, element in _INT_FIELDS if element in last and last[element][1] > 0]
        wanted.sort(key=lambda item: last[item[1]][0])
        fmt = "!"
        cursor = 0
        names: list[str] = []
        from_bytes: list[bool] = []
        for name, element in wanted:
            field_offset, length = last[element]
            if field_offset > cursor:
                fmt += f"{field_offset - cursor}x"
            if name in ("src_ip", "dst_ip"):
                fmt += f"{length}s"
                from_bytes.append(False)
            elif length in _INT_CODES:
                fmt += _INT_CODES[length]
                from_bytes.append(False)
            else:
                fmt += f"{length}s"  # unusual width (3, 5, 6, 7 bytes...)
                from_bytes.append(True)
            names.append(name)
            cursor = field_offset + length
        self._struct = struct.Struct(fmt)
        self._names = tuple(names)
        self._from_bytes = tuple(from_bytes)

    def decode(self, payload: bytes, export_time: datetime) -> list[FlowRecord]:
        if self._struct is None or self.record_length <= 0:
            return []
        unpack_from = self._struct.unpack_from
        names = self._names
        from_bytes = self._from_bytes
        address = ipaddress.IPv6Address if self._v6 else ipaddress.IPv4Address
        records: list[FlowRecord] = []
        step = self.record_length
        end = len(payload) - step
        offset = 0
        while offset <= end:
            values = unpack_from(payload, offset)
            offset += step
            fields: dict[str, Any] = {"src_port": 0, "dst_port": 0, "protocol": 0, "packets": 0, "octets": 0, "tcp_flags": 0}
            for name, value, convert in zip(names, values, from_bytes, strict=True):
                fields[name] = int.from_bytes(value, "big") if convert else value
            fields["src_ip"] = address(fields["src_ip"])
            fields["dst_ip"] = address(fields["dst_ip"])
            records.append(FlowRecord(timestamp=export_time, **fields))
        return records


class NetFlowV5Parser:
    _HEADER = struct.Struct("!HHIIIIBBH")
    _RECORD = struct.Struct("!IIIHHIIIIHHBBBBHHBBH")

    def parse(self, payload: bytes) -> list[FlowRecord]:
        if len(payload) < self._HEADER.size:
            return []

        version, count, _, unix_secs, _, _, _, _, _ = self._HEADER.unpack_from(payload)
        if version != 5:
            return []

        expected_size = self._HEADER.size + (count * self._RECORD.size)
        if len(payload) < expected_size:
            return []

        timestamp = datetime.fromtimestamp(unix_secs, tz=UTC)
        records: list[FlowRecord] = []
        offset = self._HEADER.size

        for _ in range(count):
            (
                srcaddr,
                dstaddr,
                _,
                _,
                _,
                packets,
                octets,
                _,
                _,
                src_port,
                dst_port,
                _,
                tcp_flags,
                protocol,
                _,
                _,
                _,
                _,
                _,
                _,
            ) = self._RECORD.unpack_from(payload, offset)
            offset += self._RECORD.size

            records.append(
                FlowRecord(
                    src_ip=ipaddress.IPv4Address(srcaddr),
                    dst_ip=ipaddress.IPv4Address(dstaddr),
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    packets=packets,
                    octets=octets,
                    timestamp=timestamp,
                    tcp_flags=tcp_flags,
                )
            )

        return records


class NetFlowParser:
    _V9_HEADER = struct.Struct("!HHIIII")
    _IPFIX_HEADER = struct.Struct("!HHIII")
    _SET_HEADER = struct.Struct("!HH")
    _TEMPLATE_HEADER = struct.Struct("!HH")
    _TEMPLATE_FIELD = struct.Struct("!HH")

    def __init__(self) -> None:
        self._v5_parser = NetFlowV5Parser()
        self._templates: dict[tuple[str, int, int, int], tuple[TemplateField, ...]] = {}
        self._decoders: dict[tuple[str, int, int, int], _TemplateDecoder] = {}
        self._template_counts: dict[str, int] = {}
        self._stats = ParserStats()

    def parse(self, payload: bytes, exporter_host: str) -> list[FlowRecord]:
        self._stats.total_datagrams += 1
        if (
            exporter_host in self._stats.exporters
            or len(self._stats.exporters) < MAX_TRACKED_EXPORTERS
        ):
            self._stats.exporters.add(exporter_host)

        if len(payload) < 2:
            return self._drop("Datagram shorter than version header")

        version = struct.unpack_from("!H", payload)[0]

        try:
            if version == 5:
                records = self._v5_parser.parse(payload)
                self._stats.versions_seen.add("NetFlow v5")
            elif version == 9:
                records = self._parse_netflow_v9(payload, exporter_host)
                self._stats.versions_seen.add("NetFlow v9")
            elif version == 10:
                records = self._parse_ipfix(payload, exporter_host)
                self._stats.versions_seen.add("IPFIX")
            else:
                return self._drop(f"Unsupported flow export version {version}")
        except ValueError as err:
            return self._drop(str(err))

        self._stats.parsed_datagrams += 1
        return records

    def snapshot_stats(self) -> dict[str, object]:
        return self._stats.as_dict(active_templates=len(self._templates))

    def record_rejected(self) -> None:
        """Count a datagram dropped before parsing (exporter not allowed)."""
        self._stats.rejected_datagrams += 1

    def _parse_netflow_v9(self, payload: bytes, exporter_host: str) -> list[FlowRecord]:
        if len(payload) < self._V9_HEADER.size:
            raise ValueError("NetFlow v9 datagram shorter than header")

        _, _, _, unix_secs, _, source_id = self._V9_HEADER.unpack_from(payload)
        export_time = datetime.fromtimestamp(unix_secs, tz=UTC)
        return self._parse_template_sets(
            payload=payload,
            exporter_host=exporter_host,
            version=9,
            source_id=source_id,
            export_time=export_time,
            offset=self._V9_HEADER.size,
        )

    def _parse_ipfix(self, payload: bytes, exporter_host: str) -> list[FlowRecord]:
        if len(payload) < self._IPFIX_HEADER.size:
            raise ValueError("IPFIX datagram shorter than header")

        _, message_length, export_time_seconds, _, observation_domain_id = self._IPFIX_HEADER.unpack_from(payload)
        if message_length > len(payload):
            raise ValueError("IPFIX message length exceeds datagram size")

        export_time = datetime.fromtimestamp(export_time_seconds, tz=UTC)
        return self._parse_template_sets(
            payload=payload[:message_length],
            exporter_host=exporter_host,
            version=10,
            source_id=observation_domain_id,
            export_time=export_time,
            offset=self._IPFIX_HEADER.size,
        )

    def _parse_template_sets(
        self,
        payload: bytes,
        exporter_host: str,
        version: int,
        source_id: int,
        export_time: datetime,
        offset: int,
    ) -> list[FlowRecord]:
        records: list[FlowRecord] = []

        while offset + self._SET_HEADER.size <= len(payload):
            set_id, set_length = self._SET_HEADER.unpack_from(payload, offset)
            if set_length < self._SET_HEADER.size:
                raise ValueError("Flow set length shorter than header")

            end = offset + set_length
            if end > len(payload):
                raise ValueError("Flow set length exceeds datagram size")

            set_payload = payload[offset + self._SET_HEADER.size : end]
            if set_id in {0, 2}:
                self._register_templates(set_payload, exporter_host, version, source_id)
            elif set_id in {1, 3}:
                pass
            elif set_id >= 256:
                records.extend(
                    self._parse_data_set(
                        set_payload,
                        exporter_host=exporter_host,
                        version=version,
                        source_id=source_id,
                        template_id=set_id,
                        export_time=export_time,
                    )
                )

            offset = end

        return records

    def _register_templates(self, payload: bytes, exporter_host: str, version: int, source_id: int) -> None:
        offset = 0
        while offset + self._TEMPLATE_HEADER.size <= len(payload):
            template_id, field_count = self._TEMPLATE_HEADER.unpack_from(payload, offset)
            offset += self._TEMPLATE_HEADER.size
            required_size = field_count * self._TEMPLATE_FIELD.size
            if offset + required_size > len(payload):
                raise ValueError("Template field list exceeds set payload")

            fields: list[TemplateField] = []
            for _ in range(field_count):
                field_type, field_length = self._TEMPLATE_FIELD.unpack_from(payload, offset)
                fields.append(TemplateField(field_type=field_type, field_length=field_length))
                offset += self._TEMPLATE_FIELD.size

            key = (exporter_host, version, source_id, template_id)
            if key not in self._templates:
                count = self._template_counts.get(exporter_host, 0)
                if count >= MAX_TEMPLATES_PER_EXPORTER:
                    self._stats.templates_rejected += 1
                    continue
                self._template_counts[exporter_host] = count + 1
            self._templates[key] = tuple(fields)
            self._decoders[key] = _TemplateDecoder(self._templates[key])
            self._stats.templates_registered += 1

    def _parse_data_set(
        self,
        payload: bytes,
        exporter_host: str,
        version: int,
        source_id: int,
        template_id: int,
        export_time: datetime,
    ) -> list[FlowRecord]:
        decoder = self._decoders.get((exporter_host, version, source_id, template_id))
        if decoder is None:
            self._stats.data_sets_without_template += 1
            return []
        return decoder.decode(payload, export_time)

    def _drop(self, message: str) -> list[FlowRecord]:
        self._stats.dropped_datagrams += 1
        self._stats.last_error = message
        return []



def parse_exporter_allowlist(raw: str | None) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Parse a comma/newline separated list of exporter IPs or CIDRs.

    Raises ``ValueError`` on an invalid entry.  An empty list means "accept
    datagrams from any exporter".
    """
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for token in str(raw or "").replace("\n", ",").split(","):
        token = token.strip()
        if token:
            networks.append(ipaddress.ip_network(token, strict=False))
    return networks


class NetFlowDatagramProtocol(DatagramProtocol):
    def __init__(
        self,
        callback: Callable[[list[FlowRecord]], None],
        allowed_exporters: list[ipaddress.IPv4Network | ipaddress.IPv6Network] | None = None,
    ) -> None:
        self._callback = callback
        self._parser = NetFlowParser()
        self._callback_errors: int = 0
        self._allowed_exporters = list(allowed_exporters or [])
        self._buffer: list[tuple[bytes, str]] = []
        self._flush_scheduled = False
        self._buffer_overflows = 0

    def _exporter_allowed(self, host: str) -> bool:
        if not self._allowed_exporters:
            return True
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return False
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        return any(address in network for network in self._allowed_exporters)

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if not self._exporter_allowed(addr[0]):
            self._parser.record_rejected()
            return
        if len(self._buffer) >= MAX_BUFFERED_DATAGRAMS:
            self._buffer_overflows += 1
            return
        self._buffer.append((data, addr[0]))
        if self._flush_scheduled:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            # No running loop (direct use, e.g. tests): process right away
            self.flush()
            return
        self._flush_scheduled = True
        loop.call_soon(self.flush)

    def flush(self) -> None:
        """Parse all buffered datagrams and hand the records over in one call.

        A busy exporter sends many datagrams per event-loop iteration; parsing
        them together lets the analyzer ingest one batch instead of running
        once per datagram.
        """
        self._flush_scheduled = False
        if not self._buffer:
            return
        batch, self._buffer = self._buffer, []
        records: list[FlowRecord] = []
        for data, exporter in batch:
            try:
                records.extend(self._parser.parse(data, exporter_host=exporter))
            except Exception:  # noqa: BLE001
                self._callback_errors += 1
                _LOGGER.debug("Error parsing datagram from %s", exporter, exc_info=True)
        if not records:
            return
        try:
            self._callback(records)
        except Exception:  # noqa: BLE001
            self._callback_errors += 1
            _LOGGER.debug("Error processing %d flow records", len(records), exc_info=True)

    def snapshot_stats(self) -> dict[str, object]:
        stats = self._parser.snapshot_stats()
        stats["callback_errors"] = self._callback_errors
        stats["buffer_overflows"] = self._buffer_overflows
        return stats
