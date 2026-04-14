from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from homeassistant.components.sensor import SensorEntity, SensorEntityDescription
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import HomeSecCoordinator


@dataclass(frozen=True, kw_only=True)
class HomeSecSensorDescription(SensorEntityDescription):
    value_key: str


SENSORS: tuple[HomeSecSensorDescription, ...] = (
    HomeSecSensorDescription(
        key="active_devices",
        name="HSA Active Devices",
        icon="mdi:lan-connect",
        value_key="active_devices",
    ),
    HomeSecSensorDescription(
        key="scanned_devices",
        name="HSA Scanned Devices",
        icon="mdi:access-point-network",
        value_key="scanned_devices",
    ),
    HomeSecSensorDescription(
        key="total_flows",
        name="HSA Total Flows",
        icon="mdi:chart-sankey",
        value_key="total_flows",
    ),
    HomeSecSensorDescription(
        key="open_findings",
        name="HSA Open Findings",
        icon="mdi:shield-alert-outline",
        value_key="open_findings",
    ),
    HomeSecSensorDescription(
        key="vulnerability_count",
        name="HSA Vulnerabilities",
        icon="mdi:bug-outline",
        value_key="vulnerability_count",
    ),
    HomeSecSensorDescription(
        key="suspicious_sources",
        name="HSA Suspicious Sources",
        icon="mdi:radar",
        value_key="suspicious_sources",
    ),
    HomeSecSensorDescription(
        key="high_egress_sources",
        name="HSA High Egress Sources",
        icon="mdi:upload-network-outline",
        value_key="high_egress_sources",
    ),
    HomeSecSensorDescription(
        key="nvd_keywords",
        name="HSA NVD Keywords",
        icon="mdi:database-search-outline",
        value_key="nvd_keywords",
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: HomeSecCoordinator = hass.data[DOMAIN]["entries"][entry.entry_id]["coordinator"]
    async_add_entities(HomeSecSensorEntity(coordinator, entry, description) for description in SENSORS)


class HomeSecSensorEntity(CoordinatorEntity[HomeSecCoordinator], SensorEntity):
    entity_description: HomeSecSensorDescription
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: HomeSecCoordinator,
        entry: ConfigEntry,
        description: HomeSecSensorDescription,
    ) -> None:
        super().__init__(coordinator)
        self.entity_description = description
        self._attr_unique_id = f"{entry.entry_id}-{description.key}"
        self._entry_id = entry.entry_id

    @property
    def device_info(self) -> DeviceInfo:
        return DeviceInfo(
            identifiers={(DOMAIN, self._entry_id)},
            name="Home Security Assistant",
            manufacturer="HomeSec",
        )

    @property
    def native_value(self) -> Any:
        if self.coordinator.data is None:
            return None
        if self.entity_description.key == "nvd_keywords":
            keywords = self.coordinator.data.get("nvd_keywords", [])
            return len(keywords) if keywords else 0
        return self.coordinator.data.get(self.entity_description.value_key)

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        data = self.coordinator.data
        if data is None:
            return None
        if self.entity_description.key == "active_devices":
            devices = data.get("devices", [])
            return {
                "device_count": len(devices),
                "at_risk_count": sum(1 for d in devices if d.get("at_risk")),
                "tracker_enriched_devices": data.get("tracker_enriched_devices"),
                "last_flow_at": data.get("last_flow_at"),
            }
        if self.entity_description.key == "open_findings":
            findings = data.get("findings", [])
            by_severity: dict[str, int] = {}
            for f in findings:
                sev = f.get("severity", "unknown")
                by_severity[sev] = by_severity.get(sev, 0) + 1
            return {
                "finding_count": len(findings),
                "by_severity": by_severity,
                "last_flow_at": data.get("last_flow_at"),
            }
        if self.entity_description.key == "nvd_keywords":
            keywords = data.get("nvd_keywords", [])
            attrs: dict[str, Any] = {
                "keywords": [kw["keyword"] for kw in keywords],
                "total_cached_cves": data.get("nvd_total_cves", 0),
                "nvd_min_year": data.get("nvd_min_year"),
            }
            for kw in keywords:
                attrs[kw["keyword"]] = {
                    "cve_count": kw["cve_count"],
                    "source": kw["source"],
                    "fetched_at": kw["fetched_at"],
                }
            return attrs
        return {
            "last_flow_at": data.get("last_flow_at"),
        }
