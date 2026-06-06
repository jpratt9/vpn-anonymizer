#!/usr/bin/env python3
"""VPN Anonymizer — cycle through Mullvad relays, ping-verify each, and check
whether that exit IP is flagged as VPN / datacenter / proxy (via api.ipapi.is).

Connect/verify/disconnect logic is lifted from clip_fixer's scraper/vpn.py.
Requires: the `mullvad` CLI installed, the daemon running, and an account
logged in.

Public API:
    from vpn_anonymizer import rotate
    rotate(skip=None) -> str | None   # new relay id, or None if none worked

CLI:
    vpn-anonymizer        # walks every WireGuard relay until one is clean
    python3 vpn_anonymizer.py
"""
import json
import logging
import random
import re
import subprocess
import sys
import time

logger = logging.getLogger(__name__)


def list_relays(country="us"):
    """Mullvad WireGuard relay IDs from `mullvad relay list` (e.g. us-nyc-wg-001).
    `country` is the 2-letter ISO prefix; pass None to return every country."""
    out = subprocess.run(["mullvad", "relay", "list"], capture_output=True, text=True, timeout=15).stdout
    pattern = r"\b([a-z]{2}-[a-z]+-wg-\d+)\b" if country is None \
              else rf"\b({re.escape(country)}-[a-z]+-wg-\d+)\b"
    return re.findall(pattern, out)


def connect_to_server(server_id, connect_timeout=40):
    """Set relay + connect, polling `mullvad status` until Connected. (clip_fixer vpn.py)"""
    r = subprocess.run(["mullvad", "relay", "set", "location", server_id],
                       capture_output=True, text=True, timeout=15)
    if "Relay constraints updated" not in r.stdout:
        return False
    if subprocess.run(["mullvad", "connect"], capture_output=True, text=True, timeout=30).returncode != 0:
        return False
    for _ in range(connect_timeout):
        time.sleep(1)
        status = subprocess.run(["mullvad", "status"], capture_output=True, text=True, timeout=5).stdout
        if "Connected" in status and "Connecting" not in status:
            return True
    return False


def verify_connection():
    """Ping google.com through the tunnel to confirm connectivity. (clip_fixer vpn.py)"""
    cmd = (["ping", "-n", "2", "-w", "5000", "google.com"] if sys.platform == "win32"
           else ["ping", "-c", "2", "-W", "5", "google.com"])
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=10).returncode == 0
    except subprocess.TimeoutExpired:
        return False


def disconnect():
    """Disconnect from Mullvad. (clip_fixer vpn.py)"""
    try:
        subprocess.run(["mullvad", "disconnect"], check=True, timeout=10, capture_output=True)
        time.sleep(1)
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return False


def detection_flags(api="https://api.ipapi.is/", fields=("is_vpn", "is_proxy")):
    """Check the CURRENT (tunneled) exit IP's reputation. Returns (ip, {field: bool})."""
    raw = subprocess.run(["curl", "-s", api], capture_output=True, text=True, timeout=20).stdout
    data = json.loads(raw)
    return data.get("ip", "?"), {f: bool(data.get(f, False)) for f in fields}


def rotate(skip=None, country="us"):
    """Walk the WireGuard relays for `country` (default 'us', pass None for any)
    in random order (skipping any in `skip`) and stop at the first one that
    connects + verifies + isn't flagged by ipapi.is. Returns the new relay id
    on success, or None if every candidate failed.

    On None, the tunnel is left torn down (disconnect() called)."""
    skip = set(skip) if skip else set()
    relays = [r for r in list_relays(country=country) if r not in skip]
    random.shuffle(relays)
    for server in relays:
        logger.info("Checking %s ...", server)
        if not connect_to_server(server):
            logger.info("  %s connect failed → next", server)
            continue
        if not verify_connection():
            logger.info("  %s no connectivity (ping failed) → next", server)
            disconnect()
            continue
        try:
            ip, flags = detection_flags()
        except Exception as exc:
            logger.info("  %s detection error (%s) → next", server, exc)
            continue
        hits = [name for name, flagged in flags.items() if flagged]
        if hits:
            logger.info("  %s (%s) DETECTED! → %s", server, ip, ", ".join(hits))
            continue
        logger.info("  %s (%s) clean ✓ — staying connected here, done.", server, ip)
        return server
    disconnect()
    return None


def main():
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    relays = list_relays()
    if not relays:
        sys.exit("No relays found — is the mullvad CLI installed and the daemon running?")
    print(f"Found {len(relays)} relays.\n", flush=True)
    if rotate() is None:
        print("No clean relay found.", flush=True)


if __name__ == "__main__":
    main()
