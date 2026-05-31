#!/usr/bin/env python3
"""suricata_pusher.py — Stream Suricata EVE JSON alerts to the Home Security Assistant.

Deploy this script on the Suricata host.  It tails eve-alert.json (or any EVE
log file) and streams each new alert line over a persistent TCP connection to
the HomeSec listener running on your Home Assistant instance.

Usage
-----
    python3 suricata_pusher.py [OPTIONS]

Options
-------
    --eve-file PATH     Path to Suricata EVE JSON log file
                        (default: /var/log/suricata/eve-alert.json)
    --ha-host HOST      Home Assistant hostname or IP (default: homeassistant.local)
    --ha-port PORT      HomeSec Suricata listener port (default: 6343)
    --retry-delay SECS  Seconds between reconnection attempts (default: 10)
    --from-start        Re-send the entire file from the beginning on each
                        reconnect instead of only tailing new lines (useful
                        for testing; disabled by default)

Running as a systemd service
-----------------------------
Create /etc/systemd/system/suricata-pusher.service:

    [Unit]
    Description=Suricata alert pusher for Home Security Assistant
    After=network.target suricata.service

    [Service]
    ExecStart=/usr/bin/python3 /opt/suricata_pusher.py --ha-host <HA_IP> --ha-port 6343
    Restart=always
    RestartSec=10
    User=suricata

    [Install]
    WantedBy=multi-user.target

Then:  systemctl enable --now suricata-pusher
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import socket
import time

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
_LOGGER = logging.getLogger("suricata_pusher")

# ── defaults ──────────────────────────────────────────────────────────────────
DEFAULT_EVE_FILE = "/var/log/suricata/eve-alert.json"
DEFAULT_HA_HOST = "homeassistant.local"
DEFAULT_HA_PORT = 6343
DEFAULT_RETRY_DELAY = 10
CONNECT_TIMEOUT = 10  # seconds
SEND_TIMEOUT = 30     # seconds


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Stream Suricata EVE alerts to HomeSec HA listener")
    p.add_argument("--eve-file", default=DEFAULT_EVE_FILE, help="Path to EVE JSON log file")
    p.add_argument("--ha-host", default=DEFAULT_HA_HOST, help="Home Assistant host/IP")
    p.add_argument("--ha-port", type=int, default=DEFAULT_HA_PORT, help="HomeSec listener TCP port")
    p.add_argument("--retry-delay", type=int, default=DEFAULT_RETRY_DELAY,
                help="Seconds between reconnect attempts")
    p.add_argument("--from-start", action="store_true",
                help="Send entire file from the beginning on each connect (testing)")
    return p.parse_args()


def _open_connection(host: str, port: int) -> socket.socket:
    """Open a TCP connection with a timeout; raises OSError on failure."""
    sock = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.settimeout(SEND_TIMEOUT)
    return sock


def _tail_and_push(eve_file: str, host: str, port: int, retry_delay: int, from_start: bool) -> None:
    """Main loop: tail the EVE file and push each alert line over TCP."""
    file_position: int = 0  # byte offset — resumes after reconnect

    while True:
        # Wait for the log file to exist (Suricata may not have started yet)
        if not os.path.exists(eve_file):
            _LOGGER.warning("EVE file not found: %s — retrying in %ds", eve_file, retry_delay)
            time.sleep(retry_delay)
            continue

        _LOGGER.info("Connecting to %s:%d …", host, port)
        try:
            sock = _open_connection(host, port)
        except OSError as exc:
            _LOGGER.warning("Cannot connect to %s:%d — %s. Retrying in %ds", host, port, exc, retry_delay)
            time.sleep(retry_delay)
            continue

        _LOGGER.info("Connected to HomeSec listener at %s:%d", host, port)

        try:
            with open(eve_file, encoding="utf-8", errors="replace") as fh:
                if from_start:
                    file_position = 0
                fh.seek(file_position)

                while True:
                    line = fh.readline()
                    if not line:
                        # No new data — wait briefly then check again
                        time.sleep(0.2)
                        # Detect log rotation: if file shrank, reset to start
                        try:
                            current_size = os.path.getsize(eve_file)
                        except OSError:
                            break
                        if current_size < file_position:
                            _LOGGER.info("EVE log rotation detected, resetting position")
                            file_position = 0
                            fh.seek(0)
                        continue

                    file_position = fh.tell()

                    line = line.strip()
                    if not line:
                        continue

                    # Validate it's JSON and an alert event before sending
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(entry, dict):
                        continue
                    if entry.get("event_type") != "alert":
                        continue

                    # Send as newline-terminated JSON
                    payload = (line + "\n").encode("utf-8")
                    try:
                        sock.sendall(payload)
                    except OSError as exc:
                        _LOGGER.warning("Send failed: %s — reconnecting", exc)
                        break

        except OSError as exc:
            _LOGGER.warning("File read error: %s", exc)
        finally:
            try:
                sock.close()
            except OSError:
                pass

        _LOGGER.info("Disconnected. Retrying in %ds …", retry_delay)
        time.sleep(retry_delay)


def main() -> None:
    args = _parse_args()
    _LOGGER.info(
        "suricata_pusher starting — file=%s  target=%s:%d",
        args.eve_file, args.ha_host, args.ha_port,
    )
    try:
        _tail_and_push(
            eve_file=args.eve_file,
            host=args.ha_host,
            port=args.ha_port,
            retry_delay=args.retry_delay,
            from_start=args.from_start,
        )
    except KeyboardInterrupt:
        _LOGGER.info("Stopped.")


if __name__ == "__main__":
    main()
