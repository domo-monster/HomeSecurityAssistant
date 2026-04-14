from __future__ import annotations

from asyncio import DatagramProtocol
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, UTC
import ipaddress
import logging
import struct

_LOGGER = logging.getLogger(__name__)


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
            "last_error": self.last_error,
            "versions_seen": sorted(self.versions_seen),
            "exporters": sorted(self.exporters),
        }


@dataclass(slots=True)
class FlowRecord:
    src_ip: ipaddress.IPv4Address
    dst_ip: ipaddress.IPv4Address
    src_port: int
    dst_port: int
    protocol: int
    packets: int
    octets: int
    timestamp: datetime
    tcp_flags: int


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
        self._stats = ParserStats()

    def parse(self, payload: bytes, exporter_host: str) -> list[FlowRecord]:
        self._stats.total_datagrams += 1
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

            self._templates[(exporter_host, version, source_id, template_id)] = tuple(fields)
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
        template = self._templates.get((exporter_host, version, source_id, template_id))
        if template is None:
            self._stats.data_sets_without_template += 1
            return []

        record_length = sum(field.field_length for field in template)
        if record_length <= 0:
            return []

        records: list[FlowRecord] = []
        offset = 0
        while offset + record_length <= len(payload):
            record_payload = payload[offset : offset + record_length]
            offset += record_length
            record = self._flow_record_from_template(template, record_payload, export_time)
            if record is not None:
                records.append(record)

        return records

    def _flow_record_from_template(
        self,
        template: tuple[TemplateField, ...],
        payload: bytes,
        export_time: datetime,
    ) -> FlowRecord | None:
        values: dict[int, bytes] = {}
        offset = 0
        for field in template:
            values[field.field_type] = payload[offset : offset + field.field_length]
            offset += field.field_length

        src_ip_raw = values.get(8)
        dst_ip_raw = values.get(12)
        if src_ip_raw is None or dst_ip_raw is None:
            return None
        if len(src_ip_raw) != 4 or len(dst_ip_raw) != 4:
            return None

        return FlowRecord(
            src_ip=ipaddress.IPv4Address(src_ip_raw),
            dst_ip=ipaddress.IPv4Address(dst_ip_raw),
            src_port=self._int_from_field(values.get(7)),
            dst_port=self._int_from_field(values.get(11)),
            protocol=self._int_from_field(values.get(4)),
            packets=self._int_from_field(values.get(2)),
            octets=self._int_from_field(values.get(1)),
            timestamp=export_time,
            tcp_flags=self._int_from_field(values.get(6)),
        )

    def _drop(self, message: str) -> list[FlowRecord]:
        self._stats.dropped_datagrams += 1
        self._stats.last_error = message
        return []

    def _int_from_field(self, value: bytes | None) -> int:
        if value is None:
            return 0
        return int.from_bytes(value, byteorder="big", signed=False)


class NetFlowDatagramProtocol(DatagramProtocol):
    def __init__(self, callback: Callable[[list[FlowRecord]], None]) -> None:
        self._callback = callback
        self._parser = NetFlowParser()
        self._callback_errors: int = 0

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            records = self._parser.parse(data, exporter_host=addr[0])
            if records:
                self._callback(records)
        except Exception:
            self._callback_errors += 1
            _LOGGER.debug("Error processing datagram from %s", addr[0], exc_info=True)

    def snapshot_stats(self) -> dict[str, object]:
        stats = self._parser.snapshot_stats()
        stats["callback_errors"] = self._callback_errors
        return stats
