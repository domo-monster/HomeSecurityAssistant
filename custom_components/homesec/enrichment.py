from __future__ import annotations

import ipaddress

from homeassistant.core import HomeAssistant


def collect_tracker_enrichment(hass: HomeAssistant) -> dict[str, dict[str, object]]:
    enrichment_by_ip: dict[str, dict[str, object]] = {}

    for state in hass.states.async_all("device_tracker"):
        candidate_ips: list[str] = []
        for key in ("ip", "ip_address"):
            value = state.attributes.get(key)
            if isinstance(value, str) and value:
                candidate_ips.append(value)

        multi_value = state.attributes.get("ip_addresses")
        if isinstance(multi_value, (list, tuple)):
            candidate_ips.extend(str(value) for value in multi_value if value)

        valid_ips = []
        for candidate in candidate_ips:
            try:
                address = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            valid_ips.append(str(address))

        if not valid_ips:
            continue

        payload = {
            "display_name": state.attributes.get("friendly_name") or state.name,
            "hostname": state.attributes.get("host_name") or state.attributes.get("hostname"),
            "mac_address": state.attributes.get("mac_address") or state.attributes.get("mac"),
            "manufacturer": state.attributes.get("manufacturer") or state.attributes.get("vendor"),
            "source_entity": state.entity_id,
        }

        for ip_address in valid_ips:
            existing = enrichment_by_ip.get(ip_address)
            if existing is None:
                enrichment_by_ip[ip_address] = payload.copy()
                continue

            for key, value in payload.items():
                if value and not existing.get(key):
                    existing[key] = value

    return enrichment_by_ip