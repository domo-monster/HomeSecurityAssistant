# Per-host scan overrides — design

## Goal

Let the user, from the host detail view in the panel, **disable the active scanner for a specific host** and **override the scan frequency on a per-host basis**. The global scan frequency continues to be configured through the existing Home Assistant options-flow.

## Non-goals

- No new "Settings" tab in the panel. The global `scan_interval` remains in the existing options-flow.
- No re-design of the host detail view beyond the new section.
- No retroactive change to `scan_exceptions` (CIDR/glob exclusion list) — it stays orthogonal to the new per-host toggle.

## User stories

- As an operator, I can open a host's detail panel and tick "Scan this host" off — the scanner stops probing it on the next tick, but the previously collected data stays visible.
- As an operator, I can pick a coarser frequency for a noisy IoT device (e.g. once every 24 h) without affecting how often the rest of the network is scanned.
- As an operator, I can revert a host to "inherit global" by selecting that option — the per-host override disappears.

## Architecture overview

```
┌──────────────────────────┐    POST /api/homesec/device/scan
│  Panel (homesec-panel.js)│ ─────────────────────────────────► HomeSecHostScanSettingsView
│  host detail section     │                                            │
└──────────────────────────┘                                            ▼
                                                          domain_data["host_settings"]
                                                                        │
                                       ┌────────────────────────────────┤
                                       ▼                                ▼
                          save_host_settings(...)              collector.set_host_setting(ip, ...)
                          (homesec_host_settings.yaml)                  │
                                                                        ▼
                                                          NetworkScanner.update_host_setting(ip, ...)
                                                          (mutates _host_settings, _next_due)
```

The dashboard payload exposes the in-memory `host_settings` dict so the panel can render the current state.

## Data model

New file `homesec_host_settings.yaml`, sibling to the existing `homesec_roles.yaml` / `homesec_names.yaml`.

```yaml
# Home Security Assistant — per-host scan overrides
# IP: { enabled: bool?, interval: int? } (auto-managed)
192.168.1.50:
  enabled: false
192.168.1.42:
  interval: 3600
```

Rules:

- Both `enabled` and `interval` are **optional** per entry.
- Default state: entry absent → `enabled = true`, interval inherited from global.
- A request that brings an entry back to "no override" (i.e. `enabled = true` and no `interval`) **removes** the entry rather than storing an empty record.
- Validation:
  - `interval`: integer in `[60, 604800]` (1 minute → 7 days) or `null`.
  - `enabled`: boolean.
  - IP key: parseable by `ipaddress.ip_address`.

## Backend

### `storage.py`

Add three constants/functions, parallel to the existing role/name override helpers:

- `HOST_SETTINGS_FILENAME = "homesec_host_settings.yaml"`
- `_host_settings_path(hass_config_dir) -> Path`
- `load_host_settings(hass_config_dir) -> dict[str, dict[str, Any]]` — returns `{ip: {"enabled": bool?, "interval": int?}}` filtered to valid entries; corrupt or missing file → `{}`.
- `save_host_settings(hass_config_dir, settings: dict[str, dict])` — writes YAML with the same header pattern as the other override files.

### `dashboard.py`

- In `async_setup_dashboard`, load host settings via `hass.async_add_executor_job(load_host_settings, ...)` and stash in `domain_data["host_settings"]`.
- In `build_dashboard_payload`, expose `"host_settings": domain_data.get("host_settings", {})` and keep the existing `"scan_interval"` key.
- Register a new view:

```python
class HomeSecHostScanSettingsView(HomeAssistantView):
    url = "/api/homesec/device/scan"
    name = "api:homesec:device:scan"
    requires_auth = True

    async def post(self, request): ...
```

Body: `{"ip": str, "enabled"?: bool, "interval"?: int | null}`.

Behavior:

- Validate IP and ranges. Reject with 400 on bad input.
- Merge into `domain_data["host_settings"][ip]`: only keys present in the request mutate; other keys preserved.
- If after merging the entry equals `{}` or `{"enabled": true}` with no interval, drop the entry.
- For each runtime, call `collector.set_host_setting(ip, enabled, interval)` so the scanner picks it up live.
- Persist via `save_host_settings`.
- Return `{"result": "ok"}`.

### `coordinator.py` (`HomeSecCollector`)

- Accept `host_settings` in `__init__` (or expose a setter populated from `domain_data` after setup) so the scanner is constructed with the correct initial state.
- Pass `host_settings` and the global `scan_interval` to `NetworkScanner`.
- Add `set_host_setting(ip, *, enabled=None, interval=None)`:
  - Update the local dict.
  - Forward to `self._scanner.update_host_setting(ip, enabled=enabled, interval=interval)`.

### `scanner.py` (`NetworkScanner`)

Switch the scan loop from "scan-then-sleep-global" to a tick-based scheduler.

New state:

- `self._host_settings: dict[str, dict]` (shared reference with collector — read-only from scanner's perspective; mutations happen via `update_host_setting`).
- `self._next_due: dict[str, datetime]` — IP → next-due timestamp.
- `_tick_interval = 30` seconds (constant).

New helpers:

- `_interval_for(ip) -> int` — `host_settings[ip].get("interval")` if present, else `self._scan_interval` (global).
- `_is_disabled(ip) -> bool` — `host_settings[ip].get("enabled") is False`.

Rewritten `_scan_loop`:

```
while self._running:
    try:
        await self._run_due_scan()
    except Exception:
        _LOGGER.exception(...)
    await asyncio.sleep(self._tick_interval)
```

`_run_due_scan`:

```
targets = self.get_scan_targets()
now = datetime.now(UTC)
due = [ip for ip in targets
       if not self._is_disabled(ip)
       and self._next_due.get(ip, EPOCH) <= now]
if not due:
    return
results = await scan_network(due, ports=self._ports, max_concurrent=self._max_concurrent)
for ip in due:
    self._next_due[ip] = now + timedelta(seconds=self._interval_for(ip))
# update self._hosts, last_scan stats, fire on_scan_complete (existing logic)
```

Cold start: `_next_due` is empty → first tick scans every target (current behavior on first run).

`async_trigger_scan` (manual scan): scans all non-disabled targets immediately and resets each scanned IP's `_next_due` to `now + interval_for(ip)`.

`update_host_setting(ip, *, enabled, interval)`:

- Update `self._host_settings[ip]` (drop empty entries to keep the dict tight).
- If `enabled is False`: `self._next_due.pop(ip, None)` (no point keeping a schedule for a disabled host).
- If interval changed and host was scheduled: `self._next_due[ip] = min(existing, now + new_interval)` — never delay a host beyond its new interval window.
- If host was previously disabled and is now enabled: do **not** auto-set `_next_due` — let the next tick pick it up naturally.

The `last_scan_at` / `last_scan_duration` / `last_scan_hosts` properties stay; `last_scan_hosts` becomes the count from the last *non-empty* tick.

## Frontend (`homesec-panel.js`)

### Host detail (`_hostDetail(d)`)

Insert a new section in the left column, between the metadata block and the Open Ports table:

```
┌ Active scan ─────────────────────────────────┐
│ [✓] Scan this host                           │
│ Frequency: [Inherit (5 min) ▾]               │
│              Inherit (uses global)           │
│              5 min                           │
│              15 min                          │
│              1 hour                          │
│              6 hours                         │
│              24 hours                        │
│              Custom…                         │
│ (custom selected →)                          │
│ Custom (seconds): [____] [Apply]             │
└──────────────────────────────────────────────┘
```

Implementation notes:

- Pull `host_settings` from `this._data.host_settings`. The current values for IP `d.ip`:
  - `enabled = settings[d.ip]?.enabled !== false`
  - `interval = settings[d.ip]?.interval ?? null`
- Toggle (checkbox) labeled **"Scan this host"** — `data-scanip="<ip>"`.
- Select element with preset values `inherit | 300 | 900 | 3600 | 21600 | 86400 | __custom__` — `data-scanfreq="<ip>"`.
- When `__custom__` is selected, render a number input + Apply button below the select. On Apply click, parse and POST.
- When toggle is off, the select is `disabled` to avoid confusing UI (interval is irrelevant if not scanned).
- Each change posts immediately (no global Save button), then triggers `_fetch()` to refresh.

Wire the events:

- `_onChange`: handle `[data-scanip]` (checkbox change → POST enabled) and `[data-scanfreq]` (select change → POST interval, except on `__custom__` which only swaps the UI).
- `_onClick`: handle the Apply button for the custom interval input (`[data-scancustom-apply]`).

Helper: `async _postScanSetting(ip, body) { await this._hass.callApi('POST', 'homesec/device/scan', body); await this._fetch(); }`.

### Hosts list

In `_viewHosts`, when rendering the IP cell, swap the alive-status dot for a **paused glyph** (e.g. `⏸` or a small grey square) when `host_settings[d.ip]?.enabled === false`. Tooltip: "Scan disabled". The rest of the row still renders the last known data unchanged.

## Edge cases

- **Manual trigger on a disabled host**: ignored (filtered out in `_run_due_scan` and in `async_trigger_scan`'s target filter).
- **Setting saved but coordinator dies before flush**: file persistence happens after the in-memory mutation in the same request — same risk as today's role overrides; acceptable.
- **Host setting for an IP no longer in scan targets**: harmless — `get_scan_targets()` doesn't include it, the entry just sits in the YAML until the user clears it.
- **Interval shorter than current `_tick_interval` (30 s)**: clamped at the tick floor; effective minimum frequency is 30 s. Validation rejects values below 60 s anyway.

## Testing

Manual:

1. Open a host detail, untick "Scan this host" — verify the host is greyed out in the Hosts list, the YAML file contains `enabled: false`, and the next scan cycle skips it (check logs).
2. Pick "1 hour" frequency — verify the entry is `interval: 3600` in YAML, and the host is **not** rescanned during the next tick if its previous scan was less than 1 h ago.
3. Pick "Custom" → 120 s — verify the host is rescanned at the next tick after 120 s, regardless of the global interval.
4. Pick "Inherit" — verify the entry's `interval` is dropped from YAML and the host falls back to the global cadence.
5. Restart Home Assistant — verify settings survive restart and the schedule respects them on the first tick.
6. Trigger the manual scan service — verify disabled hosts are skipped, enabled hosts are scanned regardless of due-time.
