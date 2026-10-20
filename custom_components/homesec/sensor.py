from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from homeassistant.components.sensor import (
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceEntryType, DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import HomeSecCoordinator
from .dashboard import _read_version


@dataclass(frozen=True, kw_only=True)
class HomeSecSensorDescription(SensorEntityDescription):
    value_key: str


SENSORS: tuple[HomeSecSensorDescription, ...] = (
    HomeSecSensorDescription(
        key="active_devices",
        translation_key="active_devices",
        icon="mdi:lan-connect",
        state_class=SensorStateClass.MEASUREMENT,
        value_key="active_devices",
    ),
    HomeSecSensorDescription(
        key="scanned_devices",
        translation_key="scanned_devices",
        icon="mdi:access-point-network",
        state_class=SensorStateClass.MEASUREMENT,
        value_key="scanned_devices",
    ),
    HomeSecSensorDescription(
        key="total_flows",
        translation_key="total_flows",
        icon="mdi:chart-sankey",
        # Counter restarts from zero when Home Assistant restarts
        state_class=SensorStateClass.TOTAL_INCREASING,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_key="total_flows",
    ),
    HomeSecSensorDescription(
        key="open_findings",
        translation_key="open_findings",
        icon="mdi:shield-alert-outline",
        state_class=SensorStateClass.MEASUREMENT,
        value_key="open_findings",
    ),
    HomeSecSensorDescription(
        key="vulnerability_count",
        translation_key="vulnerability_count",
        icon="mdi:bug-outline",
        state_class=SensorStateClass.MEASUREMENT,
        value_key="vulnerability_count",
    ),
    HomeSecSensorDescription(
        key="suspicious_sources",
        translation_key="suspicious_sources",
        icon="mdi:radar",
        state_class=SensorStateClass.MEASUREMENT,
        value_key="suspicious_sources",
    ),
    HomeSecSensorDescription(
        key="high_egress_sources",
        translation_key="high_egress_sources",
        icon="mdi:upload-network-outline",
        state_class=SensorStateClass.MEASUREMENT,
        value_key="high_egress_sources",
    ),
    HomeSecSensorDescription(
        key="nvd_keywords",
        translation_key="nvd_keywords",
        icon="mdi:database-search-outline",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_key="nvd_keywords",
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: HomeSecCoordinator = entry.runtime_data.coordinator
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
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name="Home Security Assistant",
            manufacturer="domo-monster",
            model="Security Assistant",
            sw_version=_read_version(),
            entry_type=DeviceEntryType.SERVICE,
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
            # Fixed attribute names (one list) instead of one attribute per keyword
            keywords = data.get("nvd_keywords", [])
            return {
                "keywords": [
                    {
                        "keyword": kw["keyword"],
                        "cve_count": kw["cve_count"],
                        "source": kw["source"],
                        "fetched_at": kw["fetched_at"],
                    }
                    for kw in keywords
                ],
                "total_cached_cves": data.get("nvd_total_cves", 0),
                "nvd_min_year": data.get("nvd_min_year"),
            }
        return {
            "last_flow_at": data.get("last_flow_at"),
        }
