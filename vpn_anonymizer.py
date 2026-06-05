#!/usr/bin/env python3
"""VPN Anonymizer — cycle through Mullvad relays, ping-verify each, and check
whether that exit IP is flagged as VPN / datacenter / proxy (via api.ipapi.is).

Connect/verify/disconnect logic is lifted from clip_fixer's scraper/vpn.py.
Requires: the `mullvad` CLI installed, the daemon running, and an account
logged in. Takes no arguments — it loops through every WireGuard relay until
you Ctrl-C.

    python3 vpn_anonymizer.py
"""
import json
import re
import subprocess
import sys
import time


def list_relays():
    """All Mullvad WireGuard relay IDs from `mullvad relay list` (e.g. us-nyc-wg-001)."""
    out = subprocess.run(["mullvad", "relay", "list"], capture_output=True, text=True, timeout=15).stdout
    return re.findall(r"\b([a-z]{2}-[a-z]+-wg-\d+)\b", out)


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


def detection_flags(api="https://api.ipapi.is/", fields=("is_vpn", "is_datacenter", "is_proxy")):
    """Check the CURRENT (tunneled) exit IP's reputation. Returns (ip, {field: bool})."""
    raw = subprocess.run(["curl", "-s", api], capture_output=True, text=True, timeout=20).stdout
    data = json.loads(raw)
    return data.get("ip", "?"), {f: bool(data.get(f, False)) for f in fields}


def main():
    relays = list_relays()
    if not relays:
        sys.exit("No relays found — is the mullvad CLI installed and the daemon running?")
    print(f"Found {len(relays)} relays.\n", flush=True)
    for server in relays:
        print(f"Checking {server} ...", flush=True)
        if not connect_to_server(server):
            print(f"  {server} connect failed → next", flush=True)
            continue
        if not verify_connection():
            print(f"  {server} no connectivity (ping failed) → next", flush=True)
            disconnect()
            continue
        try:
            ip, flags = detection_flags()
        except Exception as exc:
            print(f"  {server} detection error ({exc}) → next", flush=True)
            continue
        hits = [name for name, flagged in flags.items() if flagged]
        if hits:
            print(f"  {server} ({ip}) DETECTED! → {', '.join(hits)}", flush=True)
        else:
            print(f"  {server} ({ip}) clean ✓", flush=True)
    disconnect()


if __name__ == "__main__":
    main()
